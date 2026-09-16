rule TTP_XOR_WriteProcessMemory_93af {
  strings:
    $key_93af = { c4 dd [2] f6 ff [2] f0 ca [2] de ca [2] e1 d6 }

  condition:
    any of them
}