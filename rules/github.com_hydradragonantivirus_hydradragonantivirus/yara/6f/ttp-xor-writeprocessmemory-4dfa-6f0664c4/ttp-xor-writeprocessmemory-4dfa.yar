rule TTP_XOR_WriteProcessMemory_4dfa {
  strings:
    $key_4dfa = { 1a 88 [2] 28 aa [2] 2e 9f [2] 00 9f [2] 3f 83 }

  condition:
    any of them
}