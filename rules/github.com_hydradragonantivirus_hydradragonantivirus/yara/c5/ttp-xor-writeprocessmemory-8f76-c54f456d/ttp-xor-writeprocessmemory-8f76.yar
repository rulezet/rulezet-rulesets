rule TTP_XOR_WriteProcessMemory_8f76 {
  strings:
    $key_8f76 = { d8 04 [2] ea 26 [2] ec 13 [2] c2 13 [2] fd 0f }

  condition:
    any of them
}