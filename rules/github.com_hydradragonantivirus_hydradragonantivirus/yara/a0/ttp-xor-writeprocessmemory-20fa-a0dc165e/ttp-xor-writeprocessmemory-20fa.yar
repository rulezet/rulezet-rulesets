rule TTP_XOR_WriteProcessMemory_20fa {
  strings:
    $key_20fa = { 77 88 [2] 45 aa [2] 43 9f [2] 6d 9f [2] 52 83 }

  condition:
    any of them
}