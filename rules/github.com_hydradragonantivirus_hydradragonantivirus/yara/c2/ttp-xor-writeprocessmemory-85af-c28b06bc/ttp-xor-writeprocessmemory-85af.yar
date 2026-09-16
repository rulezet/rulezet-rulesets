rule TTP_XOR_WriteProcessMemory_85af {
  strings:
    $key_85af = { d2 dd [2] e0 ff [2] e6 ca [2] c8 ca [2] f7 d6 }

  condition:
    any of them
}