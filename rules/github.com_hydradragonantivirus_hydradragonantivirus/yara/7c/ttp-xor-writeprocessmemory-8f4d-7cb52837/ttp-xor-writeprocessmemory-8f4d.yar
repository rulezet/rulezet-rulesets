rule TTP_XOR_WriteProcessMemory_8f4d {
  strings:
    $key_8f4d = { d8 3f [2] ea 1d [2] ec 28 [2] c2 28 [2] fd 34 }

  condition:
    any of them
}