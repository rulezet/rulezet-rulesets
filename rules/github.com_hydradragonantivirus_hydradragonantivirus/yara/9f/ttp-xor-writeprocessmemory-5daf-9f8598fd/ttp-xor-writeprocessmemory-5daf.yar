rule TTP_XOR_WriteProcessMemory_5daf {
  strings:
    $key_5daf = { 0a dd [2] 38 ff [2] 3e ca [2] 10 ca [2] 2f d6 }

  condition:
    any of them
}