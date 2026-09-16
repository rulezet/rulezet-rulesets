rule TTP_XOR_WriteProcessMemory_4caf {
  strings:
    $key_4caf = { 1b dd [2] 29 ff [2] 2f ca [2] 01 ca [2] 3e d6 }

  condition:
    any of them
}