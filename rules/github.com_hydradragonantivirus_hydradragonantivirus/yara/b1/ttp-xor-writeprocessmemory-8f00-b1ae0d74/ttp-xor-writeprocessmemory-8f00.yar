rule TTP_XOR_WriteProcessMemory_8f00 {
  strings:
    $key_8f00 = { d8 72 [2] ea 50 [2] ec 65 [2] c2 65 [2] fd 79 }

  condition:
    any of them
}