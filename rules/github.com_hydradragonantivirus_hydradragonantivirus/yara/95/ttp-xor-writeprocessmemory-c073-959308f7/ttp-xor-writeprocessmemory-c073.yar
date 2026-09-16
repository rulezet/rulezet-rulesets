rule TTP_XOR_WriteProcessMemory_c073 {
  strings:
    $key_c073 = { 97 01 [2] a5 23 [2] a3 16 [2] 8d 16 [2] b2 0a }

  condition:
    any of them
}