rule TTP_XOR_WriteProcessMemory_89ee {
  strings:
    $key_89ee = { de 9c [2] ec be [2] ea 8b [2] c4 8b [2] fb 97 }

  condition:
    any of them
}