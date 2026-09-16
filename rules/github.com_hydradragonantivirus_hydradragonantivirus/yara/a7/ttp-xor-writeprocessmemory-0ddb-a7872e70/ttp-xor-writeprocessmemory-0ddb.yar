rule TTP_XOR_WriteProcessMemory_0ddb {
  strings:
    $key_0ddb = { 5a a9 [2] 68 8b [2] 6e be [2] 40 be [2] 7f a2 }

  condition:
    any of them
}