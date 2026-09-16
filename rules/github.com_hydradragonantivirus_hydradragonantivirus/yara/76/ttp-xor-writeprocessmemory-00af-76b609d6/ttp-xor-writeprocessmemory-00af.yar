rule TTP_XOR_WriteProcessMemory_00af {
  strings:
    $key_00af = { 57 dd [2] 65 ff [2] 63 ca [2] 4d ca [2] 72 d6 }

  condition:
    any of them
}