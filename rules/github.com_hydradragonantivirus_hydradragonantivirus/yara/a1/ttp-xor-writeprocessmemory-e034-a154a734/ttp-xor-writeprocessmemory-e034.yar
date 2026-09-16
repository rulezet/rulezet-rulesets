rule TTP_XOR_WriteProcessMemory_e034 {
  strings:
    $key_e034 = { b7 46 [2] 85 64 [2] 83 51 [2] ad 51 [2] 92 4d }

  condition:
    any of them
}