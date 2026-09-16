rule TTP_XOR_WriteProcessMemory_cb02 {
  strings:
    $key_cb02 = { 9c 70 [2] ae 52 [2] a8 67 [2] 86 67 [2] b9 7b }

  condition:
    any of them
}