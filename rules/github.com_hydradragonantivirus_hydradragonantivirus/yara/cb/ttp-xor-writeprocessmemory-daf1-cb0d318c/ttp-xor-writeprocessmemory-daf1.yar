rule TTP_XOR_WriteProcessMemory_daf1 {
  strings:
    $key_daf1 = { 8d 83 [2] bf a1 [2] b9 94 [2] 97 94 [2] a8 88 }

  condition:
    any of them
}