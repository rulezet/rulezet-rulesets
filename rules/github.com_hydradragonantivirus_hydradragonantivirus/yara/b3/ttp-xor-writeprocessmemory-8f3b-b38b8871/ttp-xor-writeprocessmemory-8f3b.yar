rule TTP_XOR_WriteProcessMemory_8f3b {
  strings:
    $key_8f3b = { d8 49 [2] ea 6b [2] ec 5e [2] c2 5e [2] fd 42 }

  condition:
    any of them
}