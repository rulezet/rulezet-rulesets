rule TTP_XOR_WriteProcessMemory_8f3f {
  strings:
    $key_8f3f = { d8 4d [2] ea 6f [2] ec 5a [2] c2 5a [2] fd 46 }

  condition:
    any of them
}