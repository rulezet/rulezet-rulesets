rule TTP_XOR_WriteProcessMemory_8f5f {
  strings:
    $key_8f5f = { d8 2d [2] ea 0f [2] ec 3a [2] c2 3a [2] fd 26 }

  condition:
    any of them
}