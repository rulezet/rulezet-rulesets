rule TTP_XOR_WriteProcessMemory_8f73 {
  strings:
    $key_8f73 = { d8 01 [2] ea 23 [2] ec 16 [2] c2 16 [2] fd 0a }

  condition:
    any of them
}