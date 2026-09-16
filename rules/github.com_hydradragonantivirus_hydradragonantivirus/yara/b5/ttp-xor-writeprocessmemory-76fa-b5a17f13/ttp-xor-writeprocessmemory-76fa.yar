rule TTP_XOR_WriteProcessMemory_76fa {
  strings:
    $key_76fa = { 21 88 [2] 13 aa [2] 15 9f [2] 3b 9f [2] 04 83 }

  condition:
    any of them
}