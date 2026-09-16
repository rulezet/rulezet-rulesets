rule TTP_XOR_WriteProcessMemory_897e {
  strings:
    $key_897e = { de 0c [2] ec 2e [2] ea 1b [2] c4 1b [2] fb 07 }

  condition:
    any of them
}