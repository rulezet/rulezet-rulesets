rule TTP_XOR_WriteProcessMemory_897f {
  strings:
    $key_897f = { de 0d [2] ec 2f [2] ea 1a [2] c4 1a [2] fb 06 }

  condition:
    any of them
}