rule TTP_XOR_WriteProcessMemory_8918 {
  strings:
    $key_8918 = { de 6a [2] ec 48 [2] ea 7d [2] c4 7d [2] fb 61 }

  condition:
    any of them
}