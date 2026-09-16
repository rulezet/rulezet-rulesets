rule TTP_XOR_WriteProcessMemory_95af {
  strings:
    $key_95af = { c2 dd [2] f0 ff [2] f6 ca [2] d8 ca [2] e7 d6 }

  condition:
    any of them
}