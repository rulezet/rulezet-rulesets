rule TTP_XOR_WriteProcessMemory_4baf {
  strings:
    $key_4baf = { 1c dd [2] 2e ff [2] 28 ca [2] 06 ca [2] 39 d6 }

  condition:
    any of them
}