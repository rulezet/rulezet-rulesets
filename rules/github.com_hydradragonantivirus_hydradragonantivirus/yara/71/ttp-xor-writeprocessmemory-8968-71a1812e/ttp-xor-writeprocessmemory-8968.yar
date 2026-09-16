rule TTP_XOR_WriteProcessMemory_8968 {
  strings:
    $key_8968 = { de 1a [2] ec 38 [2] ea 0d [2] c4 0d [2] fb 11 }

  condition:
    any of them
}