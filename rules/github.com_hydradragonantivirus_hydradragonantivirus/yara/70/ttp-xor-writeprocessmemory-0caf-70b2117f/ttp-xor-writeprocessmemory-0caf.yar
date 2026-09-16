rule TTP_XOR_WriteProcessMemory_0caf {
  strings:
    $key_0caf = { 5b dd [2] 69 ff [2] 6f ca [2] 41 ca [2] 7e d6 }

  condition:
    any of them
}