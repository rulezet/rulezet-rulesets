rule TTP_XOR_WriteProcessMemory_cb4b {
  strings:
    $key_cb4b = { 9c 39 [2] ae 1b [2] a8 2e [2] 86 2e [2] b9 32 }

  condition:
    any of them
}