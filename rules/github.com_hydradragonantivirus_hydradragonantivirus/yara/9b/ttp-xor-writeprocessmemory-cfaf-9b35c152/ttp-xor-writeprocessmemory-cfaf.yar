rule TTP_XOR_WriteProcessMemory_cfaf {
  strings:
    $key_cfaf = { 98 dd [2] aa ff [2] ac ca [2] 82 ca [2] bd d6 }

  condition:
    any of them
}