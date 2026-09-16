rule TTP_XOR_WriteProcessMemory_fcd6 {
  strings:
    $key_fcd6 = { ab a4 [2] 99 86 [2] 9f b3 [2] b1 b3 [2] 8e af }

  condition:
    any of them
}