rule TTP_XOR_WriteProcessMemory_41cc {
  strings:
    $key_41cc = { 16 be [2] 24 9c [2] 22 a9 [2] 0c a9 [2] 33 b5 }

  condition:
    any of them
}