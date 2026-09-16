rule TTP_XOR_WriteProcessMemory_17cc {
  strings:
    $key_17cc = { 40 be [2] 72 9c [2] 74 a9 [2] 5a a9 [2] 65 b5 }

  condition:
    any of them
}