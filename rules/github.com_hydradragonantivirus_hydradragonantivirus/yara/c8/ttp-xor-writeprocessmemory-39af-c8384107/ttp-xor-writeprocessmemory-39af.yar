rule TTP_XOR_WriteProcessMemory_39af {
  strings:
    $key_39af = { 6e dd [2] 5c ff [2] 5a ca [2] 74 ca [2] 4b d6 }

  condition:
    any of them
}