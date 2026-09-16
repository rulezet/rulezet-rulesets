rule TTP_XOR_WriteProcessMemory_1ffa {
  strings:
    $key_1ffa = { 48 88 [2] 7a aa [2] 7c 9f [2] 52 9f [2] 6d 83 }

  condition:
    any of them
}