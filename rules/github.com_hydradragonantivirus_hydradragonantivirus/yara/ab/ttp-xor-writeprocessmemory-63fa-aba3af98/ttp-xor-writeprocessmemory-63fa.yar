rule TTP_XOR_WriteProcessMemory_63fa {
  strings:
    $key_63fa = { 34 88 [2] 06 aa [2] 00 9f [2] 2e 9f [2] 11 83 }

  condition:
    any of them
}