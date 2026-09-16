rule TTP_XOR_WriteProcessMemory_13cc {
  strings:
    $key_13cc = { 44 be [2] 76 9c [2] 70 a9 [2] 5e a9 [2] 61 b5 }

  condition:
    any of them
}