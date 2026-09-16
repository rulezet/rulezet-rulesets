rule TTP_XOR_WriteProcessMemory_449a {
  strings:
    $key_449a = { 13 e8 [2] 21 ca [2] 27 ff [2] 09 ff [2] 36 e3 }

  condition:
    any of them
}