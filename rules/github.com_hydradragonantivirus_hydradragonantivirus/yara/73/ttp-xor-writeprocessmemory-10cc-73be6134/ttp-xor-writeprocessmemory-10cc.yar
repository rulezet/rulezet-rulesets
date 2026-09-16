rule TTP_XOR_WriteProcessMemory_10cc {
  strings:
    $key_10cc = { 47 be [2] 75 9c [2] 73 a9 [2] 5d a9 [2] 62 b5 }

  condition:
    any of them
}