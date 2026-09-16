rule TTP_XOR_WriteProcessMemory_80af {
  strings:
    $key_80af = { d7 dd [2] e5 ff [2] e3 ca [2] cd ca [2] f2 d6 }

  condition:
    any of them
}