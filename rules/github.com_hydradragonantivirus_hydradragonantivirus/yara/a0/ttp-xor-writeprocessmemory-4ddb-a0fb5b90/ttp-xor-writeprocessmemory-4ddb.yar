rule TTP_XOR_WriteProcessMemory_4ddb {
  strings:
    $key_4ddb = { 1a a9 [2] 28 8b [2] 2e be [2] 00 be [2] 3f a2 }

  condition:
    any of them
}