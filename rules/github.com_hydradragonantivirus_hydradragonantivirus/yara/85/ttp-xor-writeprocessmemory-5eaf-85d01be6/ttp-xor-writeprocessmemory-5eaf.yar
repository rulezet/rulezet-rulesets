rule TTP_XOR_WriteProcessMemory_5eaf {
  strings:
    $key_5eaf = { 09 dd [2] 3b ff [2] 3d ca [2] 13 ca [2] 2c d6 }

  condition:
    any of them
}