rule TTP_XOR_WriteProcessMemory_cba4 {
  strings:
    $key_cba4 = { 9c d6 [2] ae f4 [2] a8 c1 [2] 86 c1 [2] b9 dd }

  condition:
    any of them
}