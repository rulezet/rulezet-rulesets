rule TTP_XOR_WriteProcessMemory_50af {
  strings:
    $key_50af = { 07 dd [2] 35 ff [2] 33 ca [2] 1d ca [2] 22 d6 }

  condition:
    any of them
}