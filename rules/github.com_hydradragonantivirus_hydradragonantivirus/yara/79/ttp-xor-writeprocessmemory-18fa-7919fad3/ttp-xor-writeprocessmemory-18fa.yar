rule TTP_XOR_WriteProcessMemory_18fa {
  strings:
    $key_18fa = { 4f 88 [2] 7d aa [2] 7b 9f [2] 55 9f [2] 6a 83 }

  condition:
    any of them
}