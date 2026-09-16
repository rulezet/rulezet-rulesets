rule TTP_XOR_WriteProcessMemory_8911 {
  strings:
    $key_8911 = { de 63 [2] ec 41 [2] ea 74 [2] c4 74 [2] fb 68 }

  condition:
    any of them
}