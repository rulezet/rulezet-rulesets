rule TTP_XOR_WriteProcessMemory_25fa {
  strings:
    $key_25fa = { 72 88 [2] 40 aa [2] 46 9f [2] 68 9f [2] 57 83 }

  condition:
    any of them
}