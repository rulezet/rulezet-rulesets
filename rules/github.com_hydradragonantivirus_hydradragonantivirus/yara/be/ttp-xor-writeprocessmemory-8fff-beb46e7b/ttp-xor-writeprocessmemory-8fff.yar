rule TTP_XOR_WriteProcessMemory_8fff {
  strings:
    $key_8fff = { d8 8d [2] ea af [2] ec 9a [2] c2 9a [2] fd 86 }

  condition:
    any of them
}