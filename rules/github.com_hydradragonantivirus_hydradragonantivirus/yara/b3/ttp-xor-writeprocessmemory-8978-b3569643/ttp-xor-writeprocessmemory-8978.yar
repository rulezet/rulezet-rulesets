rule TTP_XOR_WriteProcessMemory_8978 {
  strings:
    $key_8978 = { de 0a [2] ec 28 [2] ea 1d [2] c4 1d [2] fb 01 }

  condition:
    any of them
}