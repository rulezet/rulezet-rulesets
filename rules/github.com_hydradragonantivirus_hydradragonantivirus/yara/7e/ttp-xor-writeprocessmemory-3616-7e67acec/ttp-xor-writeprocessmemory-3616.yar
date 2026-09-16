rule TTP_XOR_WriteProcessMemory_3616 {
  strings:
    $key_3616 = { 61 64 [2] 53 46 [2] 55 73 [2] 7b 73 [2] 44 6f }

  condition:
    any of them
}