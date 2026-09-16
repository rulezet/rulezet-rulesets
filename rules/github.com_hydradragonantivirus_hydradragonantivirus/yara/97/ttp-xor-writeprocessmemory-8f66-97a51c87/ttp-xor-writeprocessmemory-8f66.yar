rule TTP_XOR_WriteProcessMemory_8f66 {
  strings:
    $key_8f66 = { d8 14 [2] ea 36 [2] ec 03 [2] c2 03 [2] fd 1f }

  condition:
    any of them
}