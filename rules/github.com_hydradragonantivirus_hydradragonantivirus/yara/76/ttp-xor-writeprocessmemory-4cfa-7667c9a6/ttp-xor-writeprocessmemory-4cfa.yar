rule TTP_XOR_WriteProcessMemory_4cfa {
  strings:
    $key_4cfa = { 1b 88 [2] 29 aa [2] 2f 9f [2] 01 9f [2] 3e 83 }

  condition:
    any of them
}