rule TTP_XOR_WriteProcessMemory_2eaf {
  strings:
    $key_2eaf = { 79 dd [2] 4b ff [2] 4d ca [2] 63 ca [2] 5c d6 }

  condition:
    any of them
}