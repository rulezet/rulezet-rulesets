rule TTP_XOR_WriteProcessMemory_89ff {
  strings:
    $key_89ff = { de 8d [2] ec af [2] ea 9a [2] c4 9a [2] fb 86 }

  condition:
    any of them
}