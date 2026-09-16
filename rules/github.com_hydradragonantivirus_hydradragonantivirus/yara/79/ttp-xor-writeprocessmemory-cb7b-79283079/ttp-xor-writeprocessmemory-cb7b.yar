rule TTP_XOR_WriteProcessMemory_cb7b {
  strings:
    $key_cb7b = { 9c 09 [2] ae 2b [2] a8 1e [2] 86 1e [2] b9 02 }

  condition:
    any of them
}