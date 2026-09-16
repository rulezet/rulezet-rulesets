rule TTP_XOR_WriteProcessMemory_cba2 {
  strings:
    $key_cba2 = { 9c d0 [2] ae f2 [2] a8 c7 [2] 86 c7 [2] b9 db }

  condition:
    any of them
}