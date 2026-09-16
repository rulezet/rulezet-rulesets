rule TTP_XOR_WriteProcessMemory_bfaf {
  strings:
    $key_bfaf = { e8 dd [2] da ff [2] dc ca [2] f2 ca [2] cd d6 }

  condition:
    any of them
}