rule TTP_XOR_WriteProcessMemory_f2cc {
  strings:
    $key_f2cc = { a5 be [2] 97 9c [2] 91 a9 [2] bf a9 [2] 80 b5 }

  condition:
    any of them
}