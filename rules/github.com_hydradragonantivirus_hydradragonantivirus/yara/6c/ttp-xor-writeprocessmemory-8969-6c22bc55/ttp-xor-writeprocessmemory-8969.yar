rule TTP_XOR_WriteProcessMemory_8969 {
  strings:
    $key_8969 = { de 1b [2] ec 39 [2] ea 0c [2] c4 0c [2] fb 10 }

  condition:
    any of them
}