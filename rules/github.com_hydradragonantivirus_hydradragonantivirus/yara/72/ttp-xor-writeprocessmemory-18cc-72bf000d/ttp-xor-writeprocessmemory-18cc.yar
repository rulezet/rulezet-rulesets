rule TTP_XOR_WriteProcessMemory_18cc {
  strings:
    $key_18cc = { 4f be [2] 7d 9c [2] 7b a9 [2] 55 a9 [2] 6a b5 }

  condition:
    any of them
}