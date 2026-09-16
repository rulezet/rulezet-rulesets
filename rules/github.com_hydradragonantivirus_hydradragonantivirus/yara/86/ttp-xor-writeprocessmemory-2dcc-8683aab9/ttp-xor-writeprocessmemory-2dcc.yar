rule TTP_XOR_WriteProcessMemory_2dcc {
  strings:
    $key_2dcc = { 7a be [2] 48 9c [2] 4e a9 [2] 60 a9 [2] 5f b5 }

  condition:
    any of them
}