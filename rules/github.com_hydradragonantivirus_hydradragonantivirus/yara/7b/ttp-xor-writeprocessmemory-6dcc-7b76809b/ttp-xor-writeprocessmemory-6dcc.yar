rule TTP_XOR_WriteProcessMemory_6dcc {
  strings:
    $key_6dcc = { 3a be [2] 08 9c [2] 0e a9 [2] 20 a9 [2] 1f b5 }

  condition:
    any of them
}