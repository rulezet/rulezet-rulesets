rule TTP_XOR_WriteProcessMemory_5faf {
  strings:
    $key_5faf = { 08 dd [2] 3a ff [2] 3c ca [2] 12 ca [2] 2d d6 }

  condition:
    any of them
}