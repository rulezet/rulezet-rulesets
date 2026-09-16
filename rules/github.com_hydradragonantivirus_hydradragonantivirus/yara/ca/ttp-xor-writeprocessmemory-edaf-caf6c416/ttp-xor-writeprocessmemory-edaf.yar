rule TTP_XOR_WriteProcessMemory_edaf {
  strings:
    $key_edaf = { ba dd [2] 88 ff [2] 8e ca [2] a0 ca [2] 9f d6 }

  condition:
    any of them
}