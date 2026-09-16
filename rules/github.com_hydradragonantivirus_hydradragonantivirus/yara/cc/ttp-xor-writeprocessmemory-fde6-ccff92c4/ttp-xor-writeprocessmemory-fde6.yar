rule TTP_XOR_WriteProcessMemory_fde6 {
  strings:
    $key_fde6 = { aa 94 [2] 98 b6 [2] 9e 83 [2] b0 83 [2] 8f 9f }

  condition:
    any of them
}