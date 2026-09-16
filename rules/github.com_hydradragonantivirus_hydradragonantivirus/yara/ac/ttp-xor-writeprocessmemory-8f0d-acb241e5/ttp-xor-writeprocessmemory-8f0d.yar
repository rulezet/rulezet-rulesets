rule TTP_XOR_WriteProcessMemory_8f0d {
  strings:
    $key_8f0d = { d8 7f [2] ea 5d [2] ec 68 [2] c2 68 [2] fd 74 }

  condition:
    any of them
}