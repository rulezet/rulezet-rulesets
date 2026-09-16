rule TTP_XOR_WriteProcessMemory_01fa {
  strings:
    $key_01fa = { 56 88 [2] 64 aa [2] 62 9f [2] 4c 9f [2] 73 83 }

  condition:
    any of them
}