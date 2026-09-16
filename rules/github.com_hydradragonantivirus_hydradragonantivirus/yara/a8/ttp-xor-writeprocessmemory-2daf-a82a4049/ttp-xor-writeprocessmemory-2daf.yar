rule TTP_XOR_WriteProcessMemory_2daf {
  strings:
    $key_2daf = { 7a dd [2] 48 ff [2] 4e ca [2] 60 ca [2] 5f d6 }

  condition:
    any of them
}