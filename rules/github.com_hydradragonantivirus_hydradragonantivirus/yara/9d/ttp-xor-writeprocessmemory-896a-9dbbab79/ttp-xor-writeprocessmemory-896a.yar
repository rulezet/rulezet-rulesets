rule TTP_XOR_WriteProcessMemory_896a {
  strings:
    $key_896a = { de 18 [2] ec 3a [2] ea 0f [2] c4 0f [2] fb 13 }

  condition:
    any of them
}