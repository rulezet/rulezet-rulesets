rule TTP_XOR_WriteProcessMemory_29fa {
  strings:
    $key_29fa = { 7e 88 [2] 4c aa [2] 4a 9f [2] 64 9f [2] 5b 83 }

  condition:
    any of them
}