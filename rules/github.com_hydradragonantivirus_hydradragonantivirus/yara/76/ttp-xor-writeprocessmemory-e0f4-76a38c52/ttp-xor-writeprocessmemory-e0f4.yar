rule TTP_XOR_WriteProcessMemory_e0f4 {
  strings:
    $key_e0f4 = { b7 86 [2] 85 a4 [2] 83 91 [2] ad 91 [2] 92 8d }

  condition:
    any of them
}