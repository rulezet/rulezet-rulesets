rule TTP_XOR_WriteProcessMemory_89fb {
  strings:
    $key_89fb = { de 89 [2] ec ab [2] ea 9e [2] c4 9e [2] fb 82 }

  condition:
    any of them
}