rule TTP_XOR_WriteProcessMemory_15fa {
  strings:
    $key_15fa = { 42 88 [2] 70 aa [2] 76 9f [2] 58 9f [2] 67 83 }

  condition:
    any of them
}