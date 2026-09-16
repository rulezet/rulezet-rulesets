rule TTP_XOR_WriteProcessMemory_59fa {
  strings:
    $key_59fa = { 0e 88 [2] 3c aa [2] 3a 9f [2] 14 9f [2] 2b 83 }

  condition:
    any of them
}