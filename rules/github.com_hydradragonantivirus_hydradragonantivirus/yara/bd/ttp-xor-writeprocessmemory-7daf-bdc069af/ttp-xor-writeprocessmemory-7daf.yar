rule TTP_XOR_WriteProcessMemory_7daf {
  strings:
    $key_7daf = { 2a dd [2] 18 ff [2] 1e ca [2] 30 ca [2] 0f d6 }

  condition:
    any of them
}