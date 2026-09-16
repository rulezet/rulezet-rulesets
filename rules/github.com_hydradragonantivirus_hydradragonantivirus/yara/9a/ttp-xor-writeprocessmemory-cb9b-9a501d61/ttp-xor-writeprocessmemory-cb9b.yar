rule TTP_XOR_WriteProcessMemory_cb9b {
  strings:
    $key_cb9b = { 9c e9 [2] ae cb [2] a8 fe [2] 86 fe [2] b9 e2 }

  condition:
    any of them
}