rule TTP_XOR_WriteProcessMemory_cb6b {
  strings:
    $key_cb6b = { 9c 19 [2] ae 3b [2] a8 0e [2] 86 0e [2] b9 12 }

  condition:
    any of them
}