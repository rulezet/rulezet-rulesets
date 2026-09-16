rule TTP_XOR_WriteProcessMemory_66fa {
  strings:
    $key_66fa = { 31 88 [2] 03 aa [2] 05 9f [2] 2b 9f [2] 14 83 }

  condition:
    any of them
}