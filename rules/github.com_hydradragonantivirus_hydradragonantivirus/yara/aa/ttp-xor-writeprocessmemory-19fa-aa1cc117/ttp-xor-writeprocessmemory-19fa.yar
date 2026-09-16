rule TTP_XOR_WriteProcessMemory_19fa {
  strings:
    $key_19fa = { 4e 88 [2] 7c aa [2] 7a 9f [2] 54 9f [2] 6b 83 }

  condition:
    any of them
}