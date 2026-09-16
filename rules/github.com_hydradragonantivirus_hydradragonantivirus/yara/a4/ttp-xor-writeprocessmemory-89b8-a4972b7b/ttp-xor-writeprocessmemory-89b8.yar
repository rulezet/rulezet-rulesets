rule TTP_XOR_WriteProcessMemory_89b8 {
  strings:
    $key_89b8 = { de ca [2] ec e8 [2] ea dd [2] c4 dd [2] fb c1 }

  condition:
    any of them
}