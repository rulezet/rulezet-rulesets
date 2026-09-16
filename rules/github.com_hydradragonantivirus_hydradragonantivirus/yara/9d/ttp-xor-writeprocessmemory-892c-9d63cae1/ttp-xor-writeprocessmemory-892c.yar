rule TTP_XOR_WriteProcessMemory_892c {
  strings:
    $key_892c = { de 5e [2] ec 7c [2] ea 49 [2] c4 49 [2] fb 55 }

  condition:
    any of them
}