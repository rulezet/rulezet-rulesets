rule TTP_XOR_WriteProcessMemory_0fcc {
  strings:
    $key_0fcc = { 58 be [2] 6a 9c [2] 6c a9 [2] 42 a9 [2] 7d b5 }

  condition:
    any of them
}