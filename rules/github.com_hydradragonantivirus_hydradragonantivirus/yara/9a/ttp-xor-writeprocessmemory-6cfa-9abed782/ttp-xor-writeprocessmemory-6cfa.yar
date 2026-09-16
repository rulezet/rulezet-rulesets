rule TTP_XOR_WriteProcessMemory_6cfa {
  strings:
    $key_6cfa = { 3b 88 [2] 09 aa [2] 0f 9f [2] 21 9f [2] 1e 83 }

  condition:
    any of them
}