rule TTP_XOR_WriteProcessMemory_68c7 {
  strings:
    $key_68c7 = { 3f b5 [2] 0d 97 [2] 0b a2 [2] 25 a2 [2] 1a be }

  condition:
    any of them
}