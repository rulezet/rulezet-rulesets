rule TTP_XOR_WriteProcessMemory_890c {
  strings:
    $key_890c = { de 7e [2] ec 5c [2] ea 69 [2] c4 69 [2] fb 75 }

  condition:
    any of them
}