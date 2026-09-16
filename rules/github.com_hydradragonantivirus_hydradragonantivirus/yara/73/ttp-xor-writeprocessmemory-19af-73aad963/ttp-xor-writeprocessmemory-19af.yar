rule TTP_XOR_WriteProcessMemory_19af {
  strings:
    $key_19af = { 4e dd [2] 7c ff [2] 7a ca [2] 54 ca [2] 6b d6 }

  condition:
    any of them
}