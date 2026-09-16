rule TTP_XOR_WriteProcessMemory_25af {
  strings:
    $key_25af = { 72 dd [2] 40 ff [2] 46 ca [2] 68 ca [2] 57 d6 }

  condition:
    any of them
}