rule TTP_XOR_WriteProcessMemory_e036 {
  strings:
    $key_e036 = { b7 44 [2] 85 66 [2] 83 53 [2] ad 53 [2] 92 4f }

  condition:
    any of them
}