rule TTP_XOR_WriteProcessMemory_8f78 {
  strings:
    $key_8f78 = { d8 0a [2] ea 28 [2] ec 1d [2] c2 1d [2] fd 01 }

  condition:
    any of them
}