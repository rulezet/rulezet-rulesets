rule TTP_XOR_WriteProcessMemory_e8af {
  strings:
    $key_e8af = { bf dd [2] 8d ff [2] 8b ca [2] a5 ca [2] 9a d6 }

  condition:
    any of them
}