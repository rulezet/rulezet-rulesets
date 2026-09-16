rule TTP_XOR_WriteProcessMemory_5ccc {
  strings:
    $key_5ccc = { 0b be [2] 39 9c [2] 3f a9 [2] 11 a9 [2] 2e b5 }

  condition:
    any of them
}