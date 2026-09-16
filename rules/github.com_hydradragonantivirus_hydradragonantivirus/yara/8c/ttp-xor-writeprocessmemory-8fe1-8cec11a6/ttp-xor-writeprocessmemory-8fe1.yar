rule TTP_XOR_WriteProcessMemory_8fe1 {
  strings:
    $key_8fe1 = { d8 93 [2] ea b1 [2] ec 84 [2] c2 84 [2] fd 98 }

  condition:
    any of them
}