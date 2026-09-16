rule TTP_XOR_WriteProcessMemory_51fa {
  strings:
    $key_51fa = { 06 88 [2] 34 aa [2] 32 9f [2] 1c 9f [2] 23 83 }

  condition:
    any of them
}