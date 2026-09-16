rule TTP_XOR_WriteProcessMemory_e9af {
  strings:
    $key_e9af = { be dd [2] 8c ff [2] 8a ca [2] a4 ca [2] 9b d6 }

  condition:
    any of them
}