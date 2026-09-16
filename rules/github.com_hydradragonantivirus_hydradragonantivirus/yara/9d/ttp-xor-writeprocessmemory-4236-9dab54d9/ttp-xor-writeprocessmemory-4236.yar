rule TTP_XOR_WriteProcessMemory_4236 {
  strings:
    $key_4236 = { 15 44 [2] 27 66 [2] 21 53 [2] 0f 53 [2] 30 4f }

  condition:
    any of them
}