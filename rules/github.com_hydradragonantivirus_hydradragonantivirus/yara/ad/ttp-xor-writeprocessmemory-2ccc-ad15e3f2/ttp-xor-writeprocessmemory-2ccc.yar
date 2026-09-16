rule TTP_XOR_WriteProcessMemory_2ccc {
  strings:
    $key_2ccc = { 7b be [2] 49 9c [2] 4f a9 [2] 61 a9 [2] 5e b5 }

  condition:
    any of them
}