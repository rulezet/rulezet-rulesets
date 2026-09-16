rule TTP_XOR_WriteProcessMemory_28fa {
  strings:
    $key_28fa = { 7f 88 [2] 4d aa [2] 4b 9f [2] 65 9f [2] 5a 83 }

  condition:
    any of them
}