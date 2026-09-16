rule TTP_XOR_WriteProcessMemory_cb71 {
  strings:
    $key_cb71 = { 9c 03 [2] ae 21 [2] a8 14 [2] 86 14 [2] b9 08 }

  condition:
    any of them
}