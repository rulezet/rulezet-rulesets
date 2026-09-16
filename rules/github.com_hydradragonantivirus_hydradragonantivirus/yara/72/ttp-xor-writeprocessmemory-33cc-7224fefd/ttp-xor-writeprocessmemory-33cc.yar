rule TTP_XOR_WriteProcessMemory_33cc {
  strings:
    $key_33cc = { 64 be [2] 56 9c [2] 50 a9 [2] 7e a9 [2] 41 b5 }

  condition:
    any of them
}