rule TTP_XOR_WriteProcessMemory_3dad {
  strings:
    $key_3dad = { 6a df [2] 58 fd [2] 5e c8 [2] 70 c8 [2] 4f d4 }

  condition:
    any of them
}