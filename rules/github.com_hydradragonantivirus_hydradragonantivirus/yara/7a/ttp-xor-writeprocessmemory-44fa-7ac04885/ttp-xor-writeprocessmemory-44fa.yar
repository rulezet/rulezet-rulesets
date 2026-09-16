rule TTP_XOR_WriteProcessMemory_44fa {
  strings:
    $key_44fa = { 13 88 [2] 21 aa [2] 27 9f [2] 09 9f [2] 36 83 }

  condition:
    any of them
}