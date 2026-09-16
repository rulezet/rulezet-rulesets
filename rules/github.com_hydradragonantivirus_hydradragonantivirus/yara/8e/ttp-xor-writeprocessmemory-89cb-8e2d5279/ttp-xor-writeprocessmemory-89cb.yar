rule TTP_XOR_WriteProcessMemory_89cb {
  strings:
    $key_89cb = { de b9 [2] ec 9b [2] ea ae [2] c4 ae [2] fb b2 }

  condition:
    any of them
}