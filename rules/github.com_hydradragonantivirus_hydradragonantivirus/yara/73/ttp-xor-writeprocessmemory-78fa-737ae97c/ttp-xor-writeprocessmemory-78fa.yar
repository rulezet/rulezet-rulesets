rule TTP_XOR_WriteProcessMemory_78fa {
  strings:
    $key_78fa = { 2f 88 [2] 1d aa [2] 1b 9f [2] 35 9f [2] 0a 83 }

  condition:
    any of them
}