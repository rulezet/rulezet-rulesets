rule TTP_XOR_WriteProcessMemory_8f46 {
  strings:
    $key_8f46 = { d8 34 [2] ea 16 [2] ec 23 [2] c2 23 [2] fd 3f }

  condition:
    any of them
}