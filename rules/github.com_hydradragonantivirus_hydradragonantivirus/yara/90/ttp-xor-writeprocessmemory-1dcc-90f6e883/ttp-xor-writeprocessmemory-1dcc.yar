rule TTP_XOR_WriteProcessMemory_1dcc {
  strings:
    $key_1dcc = { 4a be [2] 78 9c [2] 7e a9 [2] 50 a9 [2] 6f b5 }

  condition:
    any of them
}