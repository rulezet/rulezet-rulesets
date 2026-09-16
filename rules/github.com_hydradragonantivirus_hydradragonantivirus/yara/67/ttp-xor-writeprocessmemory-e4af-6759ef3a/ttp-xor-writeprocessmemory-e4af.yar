rule TTP_XOR_WriteProcessMemory_e4af {
  strings:
    $key_e4af = { b3 dd [2] 81 ff [2] 87 ca [2] a9 ca [2] 96 d6 }

  condition:
    any of them
}