rule TTP_XOR_WriteProcessMemory_60fa {
  strings:
    $key_60fa = { 37 88 [2] 05 aa [2] 03 9f [2] 2d 9f [2] 12 83 }

  condition:
    any of them
}