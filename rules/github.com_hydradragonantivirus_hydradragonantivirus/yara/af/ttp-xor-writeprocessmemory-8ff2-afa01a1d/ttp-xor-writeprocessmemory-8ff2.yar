rule TTP_XOR_WriteProcessMemory_8ff2 {
  strings:
    $key_8ff2 = { d8 80 [2] ea a2 [2] ec 97 [2] c2 97 [2] fd 8b }

  condition:
    any of them
}