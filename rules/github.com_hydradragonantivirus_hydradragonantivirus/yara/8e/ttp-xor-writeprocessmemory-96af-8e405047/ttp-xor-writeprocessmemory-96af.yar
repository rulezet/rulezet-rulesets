rule TTP_XOR_WriteProcessMemory_96af {
  strings:
    $key_96af = { c1 dd [2] f3 ff [2] f5 ca [2] db ca [2] e4 d6 }

  condition:
    any of them
}