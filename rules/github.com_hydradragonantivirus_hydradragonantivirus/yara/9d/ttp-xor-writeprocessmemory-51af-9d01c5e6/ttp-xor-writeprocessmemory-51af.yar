rule TTP_XOR_WriteProcessMemory_51af {
  strings:
    $key_51af = { 06 dd [2] 34 ff [2] 32 ca [2] 1c ca [2] 23 d6 }

  condition:
    any of them
}