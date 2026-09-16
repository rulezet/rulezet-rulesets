rule TTP_XOR_WriteProcessMemory_8f0e {
  strings:
    $key_8f0e = { d8 7c [2] ea 5e [2] ec 6b [2] c2 6b [2] fd 77 }

  condition:
    any of them
}