rule TTP_XOR_WriteProcessMemory_b1af {
  strings:
    $key_b1af = { e6 dd [2] d4 ff [2] d2 ca [2] fc ca [2] c3 d6 }

  condition:
    any of them
}