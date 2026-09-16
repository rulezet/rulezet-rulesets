rule TTP_XOR_WriteProcessMemory_8f08 {
  strings:
    $key_8f08 = { d8 7a [2] ea 58 [2] ec 6d [2] c2 6d [2] fd 71 }

  condition:
    any of them
}