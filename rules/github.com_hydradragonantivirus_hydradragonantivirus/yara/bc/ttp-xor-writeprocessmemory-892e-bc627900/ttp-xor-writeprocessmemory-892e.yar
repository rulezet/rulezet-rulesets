rule TTP_XOR_WriteProcessMemory_892e {
  strings:
    $key_892e = { de 5c [2] ec 7e [2] ea 4b [2] c4 4b [2] fb 57 }

  condition:
    any of them
}