rule TTP_XOR_WriteProcessMemory_6caf {
  strings:
    $key_6caf = { 3b dd [2] 09 ff [2] 0f ca [2] 21 ca [2] 1e d6 }

  condition:
    any of them
}