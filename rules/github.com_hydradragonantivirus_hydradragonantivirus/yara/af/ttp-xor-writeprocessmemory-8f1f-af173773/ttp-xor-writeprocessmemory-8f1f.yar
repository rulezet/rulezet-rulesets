rule TTP_XOR_WriteProcessMemory_8f1f {
  strings:
    $key_8f1f = { d8 6d [2] ea 4f [2] ec 7a [2] c2 7a [2] fd 66 }

  condition:
    any of them
}