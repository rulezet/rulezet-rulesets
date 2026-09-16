rule TTP_XOR_WriteProcessMemory_cb55 {
  strings:
    $key_cb55 = { 9c 27 [2] ae 05 [2] a8 30 [2] 86 30 [2] b9 2c }

  condition:
    any of them
}