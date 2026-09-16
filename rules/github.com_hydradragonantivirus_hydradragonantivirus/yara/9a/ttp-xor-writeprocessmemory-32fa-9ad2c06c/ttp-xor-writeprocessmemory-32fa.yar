rule TTP_XOR_WriteProcessMemory_32fa {
  strings:
    $key_32fa = { 65 88 [2] 57 aa [2] 51 9f [2] 7f 9f [2] 40 83 }

  condition:
    any of them
}