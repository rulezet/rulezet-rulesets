rule TTP_XOR_WriteProcessMemory_2ffa {
  strings:
    $key_2ffa = { 78 88 [2] 4a aa [2] 4c 9f [2] 62 9f [2] 5d 83 }

  condition:
    any of them
}