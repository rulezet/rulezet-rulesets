rule TTP_XOR_WriteProcessMemory_8938 {
  strings:
    $key_8938 = { de 4a [2] ec 68 [2] ea 5d [2] c4 5d [2] fb 41 }

  condition:
    any of them
}