rule TTP_XOR_WriteProcessMemory_f7af {
  strings:
    $key_f7af = { a0 dd [2] 92 ff [2] 94 ca [2] ba ca [2] 85 d6 }

  condition:
    any of them
}