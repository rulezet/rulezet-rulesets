rule TTP_XOR_WriteProcessMemory_2f99 {
  strings:
    $key_2f99 = { 78 eb [2] 4a c9 [2] 4c fc [2] 62 fc [2] 5d e0 }

  condition:
    any of them
}