rule TTP_XOR_WriteProcessMemory_e1af {
  strings:
    $key_e1af = { b6 dd [2] 84 ff [2] 82 ca [2] ac ca [2] 93 d6 }

  condition:
    any of them
}