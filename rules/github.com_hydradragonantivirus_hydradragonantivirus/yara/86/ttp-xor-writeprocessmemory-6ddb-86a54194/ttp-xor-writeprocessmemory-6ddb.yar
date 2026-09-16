rule TTP_XOR_WriteProcessMemory_6ddb {
  strings:
    $key_6ddb = { 3a a9 [2] 08 8b [2] 0e be [2] 20 be [2] 1f a2 }

  condition:
    any of them
}