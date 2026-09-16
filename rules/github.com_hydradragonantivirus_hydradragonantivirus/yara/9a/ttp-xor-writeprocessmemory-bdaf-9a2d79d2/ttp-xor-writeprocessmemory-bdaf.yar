rule TTP_XOR_WriteProcessMemory_bdaf {
  strings:
    $key_bdaf = { ea dd [2] d8 ff [2] de ca [2] f0 ca [2] cf d6 }

  condition:
    any of them
}