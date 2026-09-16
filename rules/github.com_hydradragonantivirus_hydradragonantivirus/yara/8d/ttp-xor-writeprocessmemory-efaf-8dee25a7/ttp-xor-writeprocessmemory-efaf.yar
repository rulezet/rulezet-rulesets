rule TTP_XOR_WriteProcessMemory_efaf {
  strings:
    $key_efaf = { b8 dd [2] 8a ff [2] 8c ca [2] a2 ca [2] 9d d6 }

  condition:
    any of them
}