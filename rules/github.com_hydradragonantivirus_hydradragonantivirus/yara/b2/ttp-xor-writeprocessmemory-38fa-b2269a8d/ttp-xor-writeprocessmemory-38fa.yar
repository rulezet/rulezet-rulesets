rule TTP_XOR_WriteProcessMemory_38fa {
  strings:
    $key_38fa = { 6f 88 [2] 5d aa [2] 5b 9f [2] 75 9f [2] 4a 83 }

  condition:
    any of them
}