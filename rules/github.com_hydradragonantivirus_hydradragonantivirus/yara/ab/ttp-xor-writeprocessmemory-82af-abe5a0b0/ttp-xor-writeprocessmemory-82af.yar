rule TTP_XOR_WriteProcessMemory_82af {
  strings:
    $key_82af = { d5 dd [2] e7 ff [2] e1 ca [2] cf ca [2] f0 d6 }

  condition:
    any of them
}