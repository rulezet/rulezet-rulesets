rule TTP_XOR_WriteProcessMemory_c0cc {
  strings:
    $key_c0cc = { 97 be [2] a5 9c [2] a3 a9 [2] 8d a9 [2] b2 b5 }

  condition:
    any of them
}