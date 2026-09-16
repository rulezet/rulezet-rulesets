rule TTP_XOR_WriteProcessMemory_c921 {
  strings:
    $key_c921 = { 9e 53 [2] ac 71 [2] aa 44 [2] 84 44 [2] bb 58 }

  condition:
    any of them
}