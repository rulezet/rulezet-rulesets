rule TTP_XOR_WriteProcessMemory_c98d {
  strings:
    $key_c98d = { 9e ff [2] ac dd [2] aa e8 [2] 84 e8 [2] bb f4 }

  condition:
    any of them
}