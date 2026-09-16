rule TTP_XOR_WriteProcessMemory_32cc {
  strings:
    $key_32cc = { 65 be [2] 57 9c [2] 51 a9 [2] 7f a9 [2] 40 b5 }

  condition:
    any of them
}