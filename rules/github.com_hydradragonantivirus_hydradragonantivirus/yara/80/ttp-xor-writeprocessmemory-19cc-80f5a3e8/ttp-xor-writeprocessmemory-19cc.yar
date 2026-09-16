rule TTP_XOR_WriteProcessMemory_19cc {
  strings:
    $key_19cc = { 4e be [2] 7c 9c [2] 7a a9 [2] 54 a9 [2] 6b b5 }

  condition:
    any of them
}