rule TTP_XOR_WriteProcessMemory_4aea {
  strings:
    $key_4aea = { 1d 98 [2] 2f ba [2] 29 8f [2] 07 8f [2] 38 93 }

  condition:
    any of them
}