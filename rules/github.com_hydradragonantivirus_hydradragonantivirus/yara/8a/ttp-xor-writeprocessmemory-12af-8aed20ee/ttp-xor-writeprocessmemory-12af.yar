rule TTP_XOR_WriteProcessMemory_12af {
  strings:
    $key_12af = { 45 dd [2] 77 ff [2] 71 ca [2] 5f ca [2] 60 d6 }

  condition:
    any of them
}