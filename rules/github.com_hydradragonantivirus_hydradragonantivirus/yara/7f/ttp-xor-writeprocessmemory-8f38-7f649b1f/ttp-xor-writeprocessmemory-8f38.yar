rule TTP_XOR_WriteProcessMemory_8f38 {
  strings:
    $key_8f38 = { d8 4a [2] ea 68 [2] ec 5d [2] c2 5d [2] fd 41 }

  condition:
    any of them
}