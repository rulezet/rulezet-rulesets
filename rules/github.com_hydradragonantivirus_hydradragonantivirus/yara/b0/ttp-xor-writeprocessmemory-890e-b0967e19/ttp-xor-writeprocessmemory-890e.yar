rule TTP_XOR_WriteProcessMemory_890e {
  strings:
    $key_890e = { de 7c [2] ec 5e [2] ea 6b [2] c4 6b [2] fb 77 }

  condition:
    any of them
}