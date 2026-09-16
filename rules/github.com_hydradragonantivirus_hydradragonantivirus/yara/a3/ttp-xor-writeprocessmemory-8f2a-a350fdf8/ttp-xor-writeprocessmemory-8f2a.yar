rule TTP_XOR_WriteProcessMemory_8f2a {
  strings:
    $key_8f2a = { d8 58 [2] ea 7a [2] ec 4f [2] c2 4f [2] fd 53 }

  condition:
    any of them
}