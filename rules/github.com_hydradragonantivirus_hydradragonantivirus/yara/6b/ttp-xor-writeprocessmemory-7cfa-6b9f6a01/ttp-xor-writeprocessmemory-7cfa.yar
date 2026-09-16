rule TTP_XOR_WriteProcessMemory_7cfa {
  strings:
    $key_7cfa = { 2b 88 [2] 19 aa [2] 1f 9f [2] 31 9f [2] 0e 83 }

  condition:
    any of them
}