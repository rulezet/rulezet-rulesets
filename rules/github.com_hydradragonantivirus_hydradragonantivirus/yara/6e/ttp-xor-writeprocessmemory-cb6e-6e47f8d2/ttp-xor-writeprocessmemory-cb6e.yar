rule TTP_XOR_WriteProcessMemory_cb6e {
  strings:
    $key_cb6e = { 9c 1c [2] ae 3e [2] a8 0b [2] 86 0b [2] b9 17 }

  condition:
    any of them
}