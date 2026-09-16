rule TTP_XOR_WriteProcessMemory_897b {
  strings:
    $key_897b = { de 09 [2] ec 2b [2] ea 1e [2] c4 1e [2] fb 02 }

  condition:
    any of them
}