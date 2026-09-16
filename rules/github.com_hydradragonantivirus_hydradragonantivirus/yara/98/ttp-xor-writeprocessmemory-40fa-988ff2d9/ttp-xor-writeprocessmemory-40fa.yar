rule TTP_XOR_WriteProcessMemory_40fa {
  strings:
    $key_40fa = { 17 88 [2] 25 aa [2] 23 9f [2] 0d 9f [2] 32 83 }

  condition:
    any of them
}