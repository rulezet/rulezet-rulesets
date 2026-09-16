rule TTP_XOR_WriteProcessMemory_75af {
  strings:
    $key_75af = { 22 dd [2] 10 ff [2] 16 ca [2] 38 ca [2] 07 d6 }

  condition:
    any of them
}