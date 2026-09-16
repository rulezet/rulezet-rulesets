rule TTP_XOR_WriteProcessMemory_8f0f {
  strings:
    $key_8f0f = { d8 7d [2] ea 5f [2] ec 6a [2] c2 6a [2] fd 76 }

  condition:
    any of them
}