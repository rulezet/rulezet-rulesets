rule TTP_XOR_WriteProcessMemory_94af {
  strings:
    $key_94af = { c3 dd [2] f1 ff [2] f7 ca [2] d9 ca [2] e6 d6 }

  condition:
    any of them
}