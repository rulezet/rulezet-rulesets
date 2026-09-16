rule TTP_XOR_WriteProcessMemory_8f2e {
  strings:
    $key_8f2e = { d8 5c [2] ea 7e [2] ec 4b [2] c2 4b [2] fd 57 }

  condition:
    any of them
}