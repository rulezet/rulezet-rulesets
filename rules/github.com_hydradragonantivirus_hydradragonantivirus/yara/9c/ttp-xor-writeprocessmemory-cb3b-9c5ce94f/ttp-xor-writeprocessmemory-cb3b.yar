rule TTP_XOR_WriteProcessMemory_cb3b {
  strings:
    $key_cb3b = { 9c 49 [2] ae 6b [2] a8 5e [2] 86 5e [2] b9 42 }

  condition:
    any of them
}