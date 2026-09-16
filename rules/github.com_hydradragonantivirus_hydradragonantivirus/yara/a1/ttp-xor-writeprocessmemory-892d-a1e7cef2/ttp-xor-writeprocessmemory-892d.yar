rule TTP_XOR_WriteProcessMemory_892d {
  strings:
    $key_892d = { de 5f [2] ec 7d [2] ea 48 [2] c4 48 [2] fb 54 }

  condition:
    any of them
}