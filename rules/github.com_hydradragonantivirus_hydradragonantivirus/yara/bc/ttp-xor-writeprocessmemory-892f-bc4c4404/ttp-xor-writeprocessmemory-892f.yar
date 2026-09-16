rule TTP_XOR_WriteProcessMemory_892f {
  strings:
    $key_892f = { de 5d [2] ec 7f [2] ea 4a [2] c4 4a [2] fb 56 }

  condition:
    any of them
}