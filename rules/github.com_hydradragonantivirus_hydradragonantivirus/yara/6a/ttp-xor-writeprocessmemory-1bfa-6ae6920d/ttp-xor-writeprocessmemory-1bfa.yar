rule TTP_XOR_WriteProcessMemory_1bfa {
  strings:
    $key_1bfa = { 4c 88 [2] 7e aa [2] 78 9f [2] 56 9f [2] 69 83 }

  condition:
    any of them
}