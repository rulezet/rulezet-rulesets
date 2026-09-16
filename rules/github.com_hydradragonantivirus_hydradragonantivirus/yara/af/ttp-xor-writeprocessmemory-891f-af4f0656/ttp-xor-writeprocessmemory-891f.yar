rule TTP_XOR_WriteProcessMemory_891f {
  strings:
    $key_891f = { de 6d [2] ec 4f [2] ea 7a [2] c4 7a [2] fb 66 }

  condition:
    any of them
}