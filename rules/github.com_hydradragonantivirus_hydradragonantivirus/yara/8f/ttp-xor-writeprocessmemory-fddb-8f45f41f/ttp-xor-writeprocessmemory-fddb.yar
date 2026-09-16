rule TTP_XOR_WriteProcessMemory_fddb {
  strings:
    $key_fddb = { aa a9 [2] 98 8b [2] 9e be [2] b0 be [2] 8f a2 }

  condition:
    any of them
}