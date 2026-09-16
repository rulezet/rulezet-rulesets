rule TTP_XOR_WriteProcessMemory_2faf {
  strings:
    $key_2faf = { 78 dd [2] 4a ff [2] 4c ca [2] 62 ca [2] 5d d6 }

  condition:
    any of them
}