rule TTP_XOR_WriteProcessMemory_8daf {
  strings:
    $key_8daf = { da dd [2] e8 ff [2] ee ca [2] c0 ca [2] ff d6 }

  condition:
    any of them
}