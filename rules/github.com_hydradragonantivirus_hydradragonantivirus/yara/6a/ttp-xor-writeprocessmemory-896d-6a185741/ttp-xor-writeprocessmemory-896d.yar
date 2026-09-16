rule TTP_XOR_WriteProcessMemory_896d {
  strings:
    $key_896d = { de 1f [2] ec 3d [2] ea 08 [2] c4 08 [2] fb 14 }

  condition:
    any of them
}