rule TTP_XOR_WriteProcessMemory_68fa {
  strings:
    $key_68fa = { 3f 88 [2] 0d aa [2] 0b 9f [2] 25 9f [2] 1a 83 }

  condition:
    any of them
}