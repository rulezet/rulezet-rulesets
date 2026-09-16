rule TTP_XOR_WriteProcessMemory_13fa {
  strings:
    $key_13fa = { 44 88 [2] 76 aa [2] 70 9f [2] 5e 9f [2] 61 83 }

  condition:
    any of them
}