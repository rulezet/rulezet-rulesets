rule TTP_XOR_WriteProcessMemory_8f28 {
  strings:
    $key_8f28 = { d8 5a [2] ea 78 [2] ec 4d [2] c2 4d [2] fd 51 }

  condition:
    any of them
}