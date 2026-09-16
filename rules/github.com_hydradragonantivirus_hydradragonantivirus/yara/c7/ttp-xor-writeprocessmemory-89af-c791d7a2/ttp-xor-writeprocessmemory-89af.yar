rule TTP_XOR_WriteProcessMemory_89af {
  strings:
    $key_89af = { de dd [2] ec ff [2] ea ca [2] c4 ca [2] fb d6 }

  condition:
    any of them
}