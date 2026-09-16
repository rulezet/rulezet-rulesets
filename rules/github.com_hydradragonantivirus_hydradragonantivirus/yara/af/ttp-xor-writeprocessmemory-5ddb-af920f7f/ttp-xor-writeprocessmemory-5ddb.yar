rule TTP_XOR_WriteProcessMemory_5ddb {
  strings:
    $key_5ddb = { 0a a9 [2] 38 8b [2] 3e be [2] 10 be [2] 2f a2 }

  condition:
    any of them
}