rule TTP_XOR_WriteProcessMemory_fbaf {
  strings:
    $key_fbaf = { ac dd [2] 9e ff [2] 98 ca [2] b6 ca [2] 89 d6 }

  condition:
    any of them
}