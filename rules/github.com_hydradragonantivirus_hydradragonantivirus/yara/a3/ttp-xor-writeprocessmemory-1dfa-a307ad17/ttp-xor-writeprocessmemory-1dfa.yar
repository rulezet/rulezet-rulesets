rule TTP_XOR_WriteProcessMemory_1dfa {
  strings:
    $key_1dfa = { 4a 88 [2] 78 aa [2] 7e 9f [2] 50 9f [2] 6f 83 }

  condition:
    any of them
}