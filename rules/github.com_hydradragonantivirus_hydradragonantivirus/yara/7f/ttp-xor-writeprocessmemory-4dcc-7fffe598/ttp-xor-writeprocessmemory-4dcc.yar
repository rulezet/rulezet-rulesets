rule TTP_XOR_WriteProcessMemory_4dcc {
  strings:
    $key_4dcc = { 1a be [2] 28 9c [2] 2e a9 [2] 00 a9 [2] 3f b5 }

  condition:
    any of them
}