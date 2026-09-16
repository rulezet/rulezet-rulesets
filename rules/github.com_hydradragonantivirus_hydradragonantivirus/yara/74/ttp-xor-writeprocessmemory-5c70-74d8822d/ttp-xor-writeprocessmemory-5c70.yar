rule TTP_XOR_WriteProcessMemory_5c70 {
  strings:
    $key_5c70 = { 0b 02 [2] 39 20 [2] 3f 15 [2] 11 15 [2] 2e 09 }

  condition:
    any of them
}