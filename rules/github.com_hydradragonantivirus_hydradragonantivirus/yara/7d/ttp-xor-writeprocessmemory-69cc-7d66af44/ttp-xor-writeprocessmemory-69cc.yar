rule TTP_XOR_WriteProcessMemory_69cc {
  strings:
    $key_69cc = { 3e be [2] 0c 9c [2] 0a a9 [2] 24 a9 [2] 1b b5 }

  condition:
    any of them
}