rule TTP_XOR_WriteProcessMemory_8f12 {
  strings:
    $key_8f12 = { d8 60 [2] ea 42 [2] ec 77 [2] c2 77 [2] fd 6b }

  condition:
    any of them
}