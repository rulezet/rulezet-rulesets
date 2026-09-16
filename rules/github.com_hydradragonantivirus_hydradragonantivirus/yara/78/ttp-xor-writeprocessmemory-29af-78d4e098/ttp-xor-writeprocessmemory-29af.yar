rule TTP_XOR_WriteProcessMemory_29af {
  strings:
    $key_29af = { 7e dd [2] 4c ff [2] 4a ca [2] 64 ca [2] 5b d6 }

  condition:
    any of them
}