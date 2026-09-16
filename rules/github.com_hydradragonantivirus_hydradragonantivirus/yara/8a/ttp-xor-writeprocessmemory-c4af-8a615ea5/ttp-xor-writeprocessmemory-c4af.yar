rule TTP_XOR_WriteProcessMemory_c4af {
  strings:
    $key_c4af = { 93 dd [2] a1 ff [2] a7 ca [2] 89 ca [2] b6 d6 }

  condition:
    any of them
}