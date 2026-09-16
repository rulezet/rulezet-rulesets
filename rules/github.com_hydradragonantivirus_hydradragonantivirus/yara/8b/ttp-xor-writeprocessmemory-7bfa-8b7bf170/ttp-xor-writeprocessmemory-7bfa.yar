rule TTP_XOR_WriteProcessMemory_7bfa {
  strings:
    $key_7bfa = { 2c 88 [2] 1e aa [2] 18 9f [2] 36 9f [2] 09 83 }

  condition:
    any of them
}