rule TTP_XOR_WriteProcessMemory_45af {
  strings:
    $key_45af = { 12 dd [2] 20 ff [2] 26 ca [2] 08 ca [2] 37 d6 }

  condition:
    any of them
}