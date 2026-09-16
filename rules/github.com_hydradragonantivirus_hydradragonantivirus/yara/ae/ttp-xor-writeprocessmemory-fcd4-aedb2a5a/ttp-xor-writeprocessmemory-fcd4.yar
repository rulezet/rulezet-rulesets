rule TTP_XOR_WriteProcessMemory_fcd4 {
  strings:
    $key_fcd4 = { ab a6 [2] 99 84 [2] 9f b1 [2] b1 b1 [2] 8e ad }

  condition:
    any of them
}