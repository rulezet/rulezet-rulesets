rule TTP_XOR_WriteProcessMemory_6865 {
  strings:
    $key_6865 = { 3f 17 [2] 0d 35 [2] 0b 00 [2] 25 00 [2] 1a 1c }

  condition:
    any of them
}