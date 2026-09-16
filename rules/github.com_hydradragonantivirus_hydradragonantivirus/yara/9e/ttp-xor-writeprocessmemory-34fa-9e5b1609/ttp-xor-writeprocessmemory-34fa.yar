rule TTP_XOR_WriteProcessMemory_34fa {
  strings:
    $key_34fa = { 63 88 [2] 51 aa [2] 57 9f [2] 79 9f [2] 46 83 }

  condition:
    any of them
}