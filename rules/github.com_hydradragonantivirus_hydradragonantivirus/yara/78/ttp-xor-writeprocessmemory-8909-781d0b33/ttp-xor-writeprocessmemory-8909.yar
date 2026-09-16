rule TTP_XOR_WriteProcessMemory_8909 {
  strings:
    $key_8909 = { de 7b [2] ec 59 [2] ea 6c [2] c4 6c [2] fb 70 }

  condition:
    any of them
}