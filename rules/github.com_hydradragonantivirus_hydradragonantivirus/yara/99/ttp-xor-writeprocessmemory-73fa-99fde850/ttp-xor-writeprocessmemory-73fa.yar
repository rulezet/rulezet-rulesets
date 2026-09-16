rule TTP_XOR_WriteProcessMemory_73fa {
  strings:
    $key_73fa = { 24 88 [2] 16 aa [2] 10 9f [2] 3e 9f [2] 01 83 }

  condition:
    any of them
}