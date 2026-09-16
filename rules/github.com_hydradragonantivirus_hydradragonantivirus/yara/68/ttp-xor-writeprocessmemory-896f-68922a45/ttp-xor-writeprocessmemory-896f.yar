rule TTP_XOR_WriteProcessMemory_896f {
  strings:
    $key_896f = { de 1d [2] ec 3f [2] ea 0a [2] c4 0a [2] fb 16 }

  condition:
    any of them
}