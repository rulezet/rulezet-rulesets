rule TTP_XOR_WriteProcessMemory_a5af {
  strings:
    $key_a5af = { f2 dd [2] c0 ff [2] c6 ca [2] e8 ca [2] d7 d6 }

  condition:
    any of them
}