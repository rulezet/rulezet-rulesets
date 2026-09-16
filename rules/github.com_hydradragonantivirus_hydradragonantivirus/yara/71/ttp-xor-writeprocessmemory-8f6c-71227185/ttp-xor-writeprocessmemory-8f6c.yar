rule TTP_XOR_WriteProcessMemory_8f6c {
  strings:
    $key_8f6c = { d8 1e [2] ea 3c [2] ec 09 [2] c2 09 [2] fd 15 }

  condition:
    any of them
}