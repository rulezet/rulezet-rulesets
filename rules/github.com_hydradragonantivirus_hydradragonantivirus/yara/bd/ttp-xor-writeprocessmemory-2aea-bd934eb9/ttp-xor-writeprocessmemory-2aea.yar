rule TTP_XOR_WriteProcessMemory_2aea {
  strings:
    $key_2aea = { 7d 98 [2] 4f ba [2] 49 8f [2] 67 8f [2] 58 93 }

  condition:
    any of them
}