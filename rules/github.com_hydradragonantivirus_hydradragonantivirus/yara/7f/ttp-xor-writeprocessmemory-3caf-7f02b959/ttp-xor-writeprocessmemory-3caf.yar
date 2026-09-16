rule TTP_XOR_WriteProcessMemory_3caf {
  strings:
    $key_3caf = { 6b dd [2] 59 ff [2] 5f ca [2] 71 ca [2] 4e d6 }

  condition:
    any of them
}