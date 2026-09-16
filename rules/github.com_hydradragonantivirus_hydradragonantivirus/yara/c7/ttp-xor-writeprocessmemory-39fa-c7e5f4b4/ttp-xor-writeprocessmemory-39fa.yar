rule TTP_XOR_WriteProcessMemory_39fa {
  strings:
    $key_39fa = { 6e 88 [2] 5c aa [2] 5a 9f [2] 74 9f [2] 4b 83 }

  condition:
    any of them
}