rule TTP_XOR_WriteProcessMemory_d8af {
  strings:
    $key_d8af = { 8f dd [2] bd ff [2] bb ca [2] 95 ca [2] aa d6 }

  condition:
    any of them
}