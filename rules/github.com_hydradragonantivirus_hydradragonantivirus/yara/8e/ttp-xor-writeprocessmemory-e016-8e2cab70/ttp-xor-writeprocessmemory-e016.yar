rule TTP_XOR_WriteProcessMemory_e016 {
  strings:
    $key_e016 = { b7 64 [2] 85 46 [2] 83 73 [2] ad 73 [2] 92 6f }

  condition:
    any of them
}