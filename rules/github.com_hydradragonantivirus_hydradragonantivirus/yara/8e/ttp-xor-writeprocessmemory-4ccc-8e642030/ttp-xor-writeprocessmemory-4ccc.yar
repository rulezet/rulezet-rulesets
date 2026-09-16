rule TTP_XOR_WriteProcessMemory_4ccc {
  strings:
    $key_4ccc = { 1b be [2] 29 9c [2] 2f a9 [2] 01 a9 [2] 3e b5 }

  condition:
    any of them
}