rule TTP_XOR_WriteProcessMemory_2918 {
  strings:
    $key_2918 = { 7e 6a [2] 4c 48 [2] 4a 7d [2] 64 7d [2] 5b 61 }

  condition:
    any of them
}