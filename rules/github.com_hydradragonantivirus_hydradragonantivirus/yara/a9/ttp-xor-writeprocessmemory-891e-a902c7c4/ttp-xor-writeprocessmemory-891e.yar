rule TTP_XOR_WriteProcessMemory_891e {
  strings:
    $key_891e = { de 6c [2] ec 4e [2] ea 7b [2] c4 7b [2] fb 67 }

  condition:
    any of them
}