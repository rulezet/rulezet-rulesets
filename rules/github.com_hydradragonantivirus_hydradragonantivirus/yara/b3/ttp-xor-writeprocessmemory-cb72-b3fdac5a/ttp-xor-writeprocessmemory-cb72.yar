rule TTP_XOR_WriteProcessMemory_cb72 {
  strings:
    $key_cb72 = { 9c 00 [2] ae 22 [2] a8 17 [2] 86 17 [2] b9 0b }

  condition:
    any of them
}