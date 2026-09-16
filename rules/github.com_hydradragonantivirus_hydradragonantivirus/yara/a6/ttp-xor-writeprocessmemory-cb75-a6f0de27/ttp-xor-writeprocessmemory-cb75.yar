rule TTP_XOR_WriteProcessMemory_cb75 {
  strings:
    $key_cb75 = { 9c 07 [2] ae 25 [2] a8 10 [2] 86 10 [2] b9 0c }

  condition:
    any of them
}