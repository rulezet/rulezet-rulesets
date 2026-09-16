rule TTP_XOR_WriteProcessMemory_4faf {
  strings:
    $key_4faf = { 18 dd [2] 2a ff [2] 2c ca [2] 02 ca [2] 3d d6 }

  condition:
    any of them
}