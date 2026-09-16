rule TTP_XOR_WriteProcessMemory_53af {
  strings:
    $key_53af = { 04 dd [2] 36 ff [2] 30 ca [2] 1e ca [2] 21 d6 }

  condition:
    any of them
}