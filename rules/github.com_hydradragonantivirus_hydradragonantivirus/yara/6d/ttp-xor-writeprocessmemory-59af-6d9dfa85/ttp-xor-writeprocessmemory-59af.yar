rule TTP_XOR_WriteProcessMemory_59af {
  strings:
    $key_59af = { 0e dd [2] 3c ff [2] 3a ca [2] 14 ca [2] 2b d6 }

  condition:
    any of them
}