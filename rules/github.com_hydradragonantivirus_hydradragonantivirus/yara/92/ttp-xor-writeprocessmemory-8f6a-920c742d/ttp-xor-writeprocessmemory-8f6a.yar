rule TTP_XOR_WriteProcessMemory_8f6a {
  strings:
    $key_8f6a = { d8 18 [2] ea 3a [2] ec 0f [2] c2 0f [2] fd 13 }

  condition:
    any of them
}