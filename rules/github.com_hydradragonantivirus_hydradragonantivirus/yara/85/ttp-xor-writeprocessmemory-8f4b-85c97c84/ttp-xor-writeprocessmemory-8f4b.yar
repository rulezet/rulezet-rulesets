rule TTP_XOR_WriteProcessMemory_8f4b {
  strings:
    $key_8f4b = { d8 39 [2] ea 1b [2] ec 2e [2] c2 2e [2] fd 32 }

  condition:
    any of them
}