rule TTP_XOR_WriteProcessMemory_e023 {
  strings:
    $key_e023 = { b7 51 [2] 85 73 [2] 83 46 [2] ad 46 [2] 92 5a }

  condition:
    any of them
}