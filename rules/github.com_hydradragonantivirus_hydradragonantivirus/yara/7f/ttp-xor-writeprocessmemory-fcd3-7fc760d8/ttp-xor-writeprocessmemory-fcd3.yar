rule TTP_XOR_WriteProcessMemory_fcd3 {
  strings:
    $key_fcd3 = { ab a1 [2] 99 83 [2] 9f b6 [2] b1 b6 [2] 8e aa }

  condition:
    any of them
}