rule TTP_XOR_WriteProcessMemory_898d {
  strings:
    $key_898d = { de ff [2] ec dd [2] ea e8 [2] c4 e8 [2] fb f4 }

  condition:
    any of them
}