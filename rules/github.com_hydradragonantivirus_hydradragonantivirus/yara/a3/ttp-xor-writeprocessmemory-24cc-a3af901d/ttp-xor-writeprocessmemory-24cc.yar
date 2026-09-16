rule TTP_XOR_WriteProcessMemory_24cc {
  strings:
    $key_24cc = { 73 be [2] 41 9c [2] 47 a9 [2] 69 a9 [2] 56 b5 }

  condition:
    any of them
}