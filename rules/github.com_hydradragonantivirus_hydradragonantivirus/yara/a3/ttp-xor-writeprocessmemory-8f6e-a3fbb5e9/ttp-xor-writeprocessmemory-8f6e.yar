rule TTP_XOR_WriteProcessMemory_8f6e {
  strings:
    $key_8f6e = { d8 1c [2] ea 3e [2] ec 0b [2] c2 0b [2] fd 17 }

  condition:
    any of them
}