rule TTP_XOR_WriteProcessMemory_58c7 {
  strings:
    $key_58c7 = { 0f b5 [2] 3d 97 [2] 3b a2 [2] 15 a2 [2] 2a be }

  condition:
    any of them
}