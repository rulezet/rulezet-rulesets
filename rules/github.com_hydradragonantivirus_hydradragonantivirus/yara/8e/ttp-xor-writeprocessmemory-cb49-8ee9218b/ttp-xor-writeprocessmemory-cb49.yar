rule TTP_XOR_WriteProcessMemory_cb49 {
  strings:
    $key_cb49 = { 9c 3b [2] ae 19 [2] a8 2c [2] 86 2c [2] b9 30 }

  condition:
    any of them
}