rule TTP_XOR_WriteProcessMemory_d1fa {
  strings:
    $key_d1fa = { 86 88 [2] b4 aa [2] b2 9f [2] 9c 9f [2] a3 83 }

  condition:
    any of them
}