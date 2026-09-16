rule TTP_XOR_WriteProcessMemory_8f26 {
  strings:
    $key_8f26 = { d8 54 [2] ea 76 [2] ec 43 [2] c2 43 [2] fd 5f }

  condition:
    any of them
}