rule TTP_XOR_WriteProcessMemory_1ccc {
  strings:
    $key_1ccc = { 4b be [2] 79 9c [2] 7f a9 [2] 51 a9 [2] 6e b5 }

  condition:
    any of them
}