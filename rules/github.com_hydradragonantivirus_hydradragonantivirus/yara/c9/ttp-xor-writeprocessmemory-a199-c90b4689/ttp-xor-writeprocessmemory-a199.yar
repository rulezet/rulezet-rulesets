rule TTP_XOR_WriteProcessMemory_a199 {
  strings:
    $key_a199 = { f6 eb [2] c4 c9 [2] c2 fc [2] ec fc [2] d3 e0 }

  condition:
    any of them
}