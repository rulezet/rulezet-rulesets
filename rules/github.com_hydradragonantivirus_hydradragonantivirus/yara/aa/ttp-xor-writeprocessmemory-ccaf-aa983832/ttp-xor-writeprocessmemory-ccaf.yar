rule TTP_XOR_WriteProcessMemory_ccaf {
  strings:
    $key_ccaf = { 9b dd [2] a9 ff [2] af ca [2] 81 ca [2] be d6 }

  condition:
    any of them
}