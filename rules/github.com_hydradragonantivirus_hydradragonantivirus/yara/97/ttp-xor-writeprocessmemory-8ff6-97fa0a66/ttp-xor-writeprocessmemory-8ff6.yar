rule TTP_XOR_WriteProcessMemory_8ff6 {
  strings:
    $key_8ff6 = { d8 84 [2] ea a6 [2] ec 93 [2] c2 93 [2] fd 8f }

  condition:
    any of them
}