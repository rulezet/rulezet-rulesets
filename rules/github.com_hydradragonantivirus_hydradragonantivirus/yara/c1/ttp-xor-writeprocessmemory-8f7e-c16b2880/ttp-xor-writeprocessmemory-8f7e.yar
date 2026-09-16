rule TTP_XOR_WriteProcessMemory_8f7e {
  strings:
    $key_8f7e = { d8 0c [2] ea 2e [2] ec 1b [2] c2 1b [2] fd 07 }

  condition:
    any of them
}