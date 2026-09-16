rule TTP_XOR_WriteProcessMemory_09af {
  strings:
    $key_09af = { 5e dd [2] 6c ff [2] 6a ca [2] 44 ca [2] 7b d6 }

  condition:
    any of them
}