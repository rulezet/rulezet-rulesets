rule TTP_XOR_WriteProcessMemory_8f18 {
  strings:
    $key_8f18 = { d8 6a [2] ea 48 [2] ec 7d [2] c2 7d [2] fd 61 }

  condition:
    any of them
}