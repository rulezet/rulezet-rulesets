rule TTP_XOR_WriteProcessMemory_54fa {
  strings:
    $key_54fa = { 03 88 [2] 31 aa [2] 37 9f [2] 19 9f [2] 26 83 }

  condition:
    any of them
}