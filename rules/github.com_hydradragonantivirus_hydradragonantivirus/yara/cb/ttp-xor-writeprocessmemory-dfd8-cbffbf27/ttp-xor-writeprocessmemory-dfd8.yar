rule TTP_XOR_WriteProcessMemory_dfd8 {
  strings:
    $key_dfd8 = { 88 aa [2] ba 88 [2] bc bd [2] 92 bd [2] ad a1 }

  condition:
    any of them
}