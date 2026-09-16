rule TTP_XOR_WriteProcessMemory_3961 {
  strings:
    $key_3961 = { 6e 13 [2] 5c 31 [2] 5a 04 [2] 74 04 [2] 4b 18 }

  condition:
    any of them
}