rule TTP_XOR_WriteProcessMemory_5caf {
  strings:
    $key_5caf = { 0b dd [2] 39 ff [2] 3f ca [2] 11 ca [2] 2e d6 }

  condition:
    any of them
}