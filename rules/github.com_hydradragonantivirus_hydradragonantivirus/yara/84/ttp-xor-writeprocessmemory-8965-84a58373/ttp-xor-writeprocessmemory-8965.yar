rule TTP_XOR_WriteProcessMemory_8965 {
  strings:
    $key_8965 = { de 17 [2] ec 35 [2] ea 00 [2] c4 00 [2] fb 1c }

  condition:
    any of them
}