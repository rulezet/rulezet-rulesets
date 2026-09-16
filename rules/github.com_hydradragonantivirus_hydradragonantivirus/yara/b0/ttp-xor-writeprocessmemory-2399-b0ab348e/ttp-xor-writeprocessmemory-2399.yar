rule TTP_XOR_WriteProcessMemory_2399 {
  strings:
    $key_2399 = { 74 eb [2] 46 c9 [2] 40 fc [2] 6e fc [2] 51 e0 }

  condition:
    any of them
}