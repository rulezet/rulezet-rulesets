rule TTP_XOR_WriteProcessMemory_89fe {
  strings:
    $key_89fe = { de 8c [2] ec ae [2] ea 9b [2] c4 9b [2] fb 87 }

  condition:
    any of them
}