rule TTP_XOR_WriteProcessMemory_239a {
  strings:
    $key_239a = { 74 e8 [2] 46 ca [2] 40 ff [2] 6e ff [2] 51 e3 }

  condition:
    any of them
}