rule TTP_XOR_WriteProcessMemory_6baf {
  strings:
    $key_6baf = { 3c dd [2] 0e ff [2] 08 ca [2] 26 ca [2] 19 d6 }

  condition:
    any of them
}