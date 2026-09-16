rule TTP_XOR_WriteProcessMemory_0ccc {
  strings:
    $key_0ccc = { 5b be [2] 69 9c [2] 6f a9 [2] 41 a9 [2] 7e b5 }

  condition:
    any of them
}