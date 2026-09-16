rule TTP_XOR_WriteProcessMemory_30af {
  strings:
    $key_30af = { 67 dd [2] 55 ff [2] 53 ca [2] 7d ca [2] 42 d6 }

  condition:
    any of them
}