rule TTP_XOR_WriteProcessMemory_72fa {
  strings:
    $key_72fa = { 25 88 [2] 17 aa [2] 11 9f [2] 3f 9f [2] 00 83 }

  condition:
    any of them
}