rule TTP_XOR_WriteProcessMemory_8f79 {
  strings:
    $key_8f79 = { d8 0b [2] ea 29 [2] ec 1c [2] c2 1c [2] fd 00 }

  condition:
    any of them
}