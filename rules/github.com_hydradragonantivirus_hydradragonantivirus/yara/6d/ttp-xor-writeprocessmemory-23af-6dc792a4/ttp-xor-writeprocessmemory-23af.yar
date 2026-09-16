rule TTP_XOR_WriteProcessMemory_23af {
  strings:
    $key_23af = { 74 dd [2] 46 ff [2] 40 ca [2] 6e ca [2] 51 d6 }

  condition:
    any of them
}