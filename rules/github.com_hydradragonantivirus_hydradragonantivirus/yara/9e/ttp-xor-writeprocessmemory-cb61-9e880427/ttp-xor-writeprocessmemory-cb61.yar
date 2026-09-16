rule TTP_XOR_WriteProcessMemory_cb61 {
  strings:
    $key_cb61 = { 9c 13 [2] ae 31 [2] a8 04 [2] 86 04 [2] b9 18 }

  condition:
    any of them
}