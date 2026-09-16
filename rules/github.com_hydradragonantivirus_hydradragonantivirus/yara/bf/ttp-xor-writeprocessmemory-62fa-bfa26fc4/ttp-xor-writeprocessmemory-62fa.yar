rule TTP_XOR_WriteProcessMemory_62fa {
  strings:
    $key_62fa = { 35 88 [2] 07 aa [2] 01 9f [2] 2f 9f [2] 10 83 }

  condition:
    any of them
}