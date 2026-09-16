rule TTP_XOR_WriteProcessMemory_8f2f {
  strings:
    $key_8f2f = { d8 5d [2] ea 7f [2] ec 4a [2] c2 4a [2] fd 56 }

  condition:
    any of them
}