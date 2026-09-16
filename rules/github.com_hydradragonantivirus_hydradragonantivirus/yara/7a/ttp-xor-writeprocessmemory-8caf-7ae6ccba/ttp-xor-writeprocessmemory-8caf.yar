rule TTP_XOR_WriteProcessMemory_8caf {
  strings:
    $key_8caf = { db dd [2] e9 ff [2] ef ca [2] c1 ca [2] fe d6 }

  condition:
    any of them
}