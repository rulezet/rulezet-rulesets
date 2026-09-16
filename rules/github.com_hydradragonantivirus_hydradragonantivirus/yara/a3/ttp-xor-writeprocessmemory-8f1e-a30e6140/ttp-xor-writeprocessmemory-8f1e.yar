rule TTP_XOR_WriteProcessMemory_8f1e {
  strings:
    $key_8f1e = { d8 6c [2] ea 4e [2] ec 7b [2] c2 7b [2] fd 67 }

  condition:
    any of them
}