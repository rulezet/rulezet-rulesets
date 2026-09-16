rule TTP_XOR_WriteProcessMemory_894c {
  strings:
    $key_894c = { de 3e [2] ec 1c [2] ea 29 [2] c4 29 [2] fb 35 }

  condition:
    any of them
}