rule TTP_XOR_WriteProcessMemory_5bfa {
  strings:
    $key_5bfa = { 0c 88 [2] 3e aa [2] 38 9f [2] 16 9f [2] 29 83 }

  condition:
    any of them
}