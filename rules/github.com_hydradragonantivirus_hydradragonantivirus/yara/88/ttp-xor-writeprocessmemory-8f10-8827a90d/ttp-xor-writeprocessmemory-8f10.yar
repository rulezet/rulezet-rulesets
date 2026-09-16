rule TTP_XOR_WriteProcessMemory_8f10 {
  strings:
    $key_8f10 = { d8 62 [2] ea 40 [2] ec 75 [2] c2 75 [2] fd 69 }

  condition:
    any of them
}