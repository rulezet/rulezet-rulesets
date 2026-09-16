rule TTP_XOR_WriteProcessMemory_89ed {
  strings:
    $key_89ed = { de 9f [2] ec bd [2] ea 88 [2] c4 88 [2] fb 94 }

  condition:
    any of them
}