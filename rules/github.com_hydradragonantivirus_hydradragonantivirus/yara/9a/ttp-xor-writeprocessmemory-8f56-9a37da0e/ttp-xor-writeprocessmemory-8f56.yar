rule TTP_XOR_WriteProcessMemory_8f56 {
  strings:
    $key_8f56 = { d8 24 [2] ea 06 [2] ec 33 [2] c2 33 [2] fd 2f }

  condition:
    any of them
}