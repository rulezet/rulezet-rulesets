rule TTP_XOR_WriteProcessMemory_16fa {
  strings:
    $key_16fa = { 41 88 [2] 73 aa [2] 75 9f [2] 5b 9f [2] 64 83 }

  condition:
    any of them
}