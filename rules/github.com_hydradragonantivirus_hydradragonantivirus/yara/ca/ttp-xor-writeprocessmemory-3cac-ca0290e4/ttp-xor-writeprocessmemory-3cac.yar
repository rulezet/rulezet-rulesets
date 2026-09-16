rule TTP_XOR_WriteProcessMemory_3cac {
  strings:
    $key_3cac = { 6b de [2] 59 fc [2] 5f c9 [2] 71 c9 [2] 4e d5 }

  condition:
    any of them
}