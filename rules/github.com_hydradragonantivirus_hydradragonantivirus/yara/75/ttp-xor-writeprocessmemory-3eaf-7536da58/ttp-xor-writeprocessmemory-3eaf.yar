rule TTP_XOR_WriteProcessMemory_3eaf {
  strings:
    $key_3eaf = { 69 dd [2] 5b ff [2] 5d ca [2] 73 ca [2] 4c d6 }

  condition:
    any of them
}