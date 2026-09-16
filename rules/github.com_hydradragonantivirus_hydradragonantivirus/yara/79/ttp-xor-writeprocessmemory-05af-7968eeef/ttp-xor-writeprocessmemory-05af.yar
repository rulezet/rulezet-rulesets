rule TTP_XOR_WriteProcessMemory_05af {
  strings:
    $key_05af = { 52 dd [2] 60 ff [2] 66 ca [2] 48 ca [2] 77 d6 }

  condition:
    any of them
}