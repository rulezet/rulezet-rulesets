rule TTP_XOR_WriteProcessMemory_89a7 {
  strings:
    $key_89a7 = { de d5 [2] ec f7 [2] ea c2 [2] c4 c2 [2] fb de }

  condition:
    any of them
}