rule TTP_XOR_WriteProcessMemory_8f1a {
  strings:
    $key_8f1a = { d8 68 [2] ea 4a [2] ec 7f [2] c2 7f [2] fd 63 }

  condition:
    any of them
}