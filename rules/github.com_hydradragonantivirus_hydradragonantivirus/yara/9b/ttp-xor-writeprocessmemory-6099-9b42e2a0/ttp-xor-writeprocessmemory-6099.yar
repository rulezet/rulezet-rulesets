rule TTP_XOR_WriteProcessMemory_6099 {
  strings:
    $key_6099 = { 37 eb [2] 05 c9 [2] 03 fc [2] 2d fc [2] 12 e0 }

  condition:
    any of them
}