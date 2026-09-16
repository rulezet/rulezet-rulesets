rule TTP_XOR_WriteProcessMemory_fcd1 {
  strings:
    $key_fcd1 = { ab a3 [2] 99 81 [2] 9f b4 [2] b1 b4 [2] 8e a8 }

  condition:
    any of them
}