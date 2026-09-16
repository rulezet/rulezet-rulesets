rule TTP_XOR_WriteProcessMemory_86af {
  strings:
    $key_86af = { d1 dd [2] e3 ff [2] e5 ca [2] cb ca [2] f4 d6 }

  condition:
    any of them
}