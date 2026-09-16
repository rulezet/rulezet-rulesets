rule TTP_XOR_WriteProcessMemory_50fa {
  strings:
    $key_50fa = { 07 88 [2] 35 aa [2] 33 9f [2] 1d 9f [2] 22 83 }

  condition:
    any of them
}