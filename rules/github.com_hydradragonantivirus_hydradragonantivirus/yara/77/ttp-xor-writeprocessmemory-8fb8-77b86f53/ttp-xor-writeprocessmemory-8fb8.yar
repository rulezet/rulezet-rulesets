rule TTP_XOR_WriteProcessMemory_8fb8 {
  strings:
    $key_8fb8 = { d8 ca [2] ea e8 [2] ec dd [2] c2 dd [2] fd c1 }

  condition:
    any of them
}