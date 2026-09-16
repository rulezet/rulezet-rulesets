rule TTP_XOR_WriteProcessMemory_7dcc {
  strings:
    $key_7dcc = { 2a be [2] 18 9c [2] 1e a9 [2] 30 a9 [2] 0f b5 }

  condition:
    any of them
}