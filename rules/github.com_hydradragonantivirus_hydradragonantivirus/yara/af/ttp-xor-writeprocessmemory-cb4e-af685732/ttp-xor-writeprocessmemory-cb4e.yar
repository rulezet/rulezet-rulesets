rule TTP_XOR_WriteProcessMemory_cb4e {
  strings:
    $key_cb4e = { 9c 3c [2] ae 1e [2] a8 2b [2] 86 2b [2] b9 37 }

  condition:
    any of them
}