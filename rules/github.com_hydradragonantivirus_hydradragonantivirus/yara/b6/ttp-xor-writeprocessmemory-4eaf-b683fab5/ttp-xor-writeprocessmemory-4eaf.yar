rule TTP_XOR_WriteProcessMemory_4eaf {
  strings:
    $key_4eaf = { 19 dd [2] 2b ff [2] 2d ca [2] 03 ca [2] 3c d6 }

  condition:
    any of them
}