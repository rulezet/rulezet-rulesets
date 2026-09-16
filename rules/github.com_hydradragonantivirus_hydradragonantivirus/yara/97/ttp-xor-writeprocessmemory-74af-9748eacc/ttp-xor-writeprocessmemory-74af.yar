rule TTP_XOR_WriteProcessMemory_74af {
  strings:
    $key_74af = { 23 dd [2] 11 ff [2] 17 ca [2] 39 ca [2] 06 d6 }

  condition:
    any of them
}