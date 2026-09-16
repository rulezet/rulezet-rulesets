rule TTP_XOR_WriteProcessMemory_e5af {
  strings:
    $key_e5af = { b2 dd [2] 80 ff [2] 86 ca [2] a8 ca [2] 97 d6 }

  condition:
    any of them
}