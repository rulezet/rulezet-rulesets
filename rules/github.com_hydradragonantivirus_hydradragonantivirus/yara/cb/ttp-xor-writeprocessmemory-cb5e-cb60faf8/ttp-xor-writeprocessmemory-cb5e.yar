rule TTP_XOR_WriteProcessMemory_cb5e {
  strings:
    $key_cb5e = { 9c 2c [2] ae 0e [2] a8 3b [2] 86 3b [2] b9 27 }

  condition:
    any of them
}