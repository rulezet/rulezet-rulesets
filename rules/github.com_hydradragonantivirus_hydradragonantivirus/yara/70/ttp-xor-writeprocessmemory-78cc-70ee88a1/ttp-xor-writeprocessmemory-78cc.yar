rule TTP_XOR_WriteProcessMemory_78cc {
  strings:
    $key_78cc = { 2f be [2] 1d 9c [2] 1b a9 [2] 35 a9 [2] 0a b5 }

  condition:
    any of them
}