rule TTP_XOR_WriteProcessMemory_8f53 {
  strings:
    $key_8f53 = { d8 21 [2] ea 03 [2] ec 36 [2] c2 36 [2] fd 2a }

  condition:
    any of them
}