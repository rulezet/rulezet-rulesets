rule TTP_XOR_WriteProcessMemory_1aea {
  strings:
    $key_1aea = { 4d 98 [2] 7f ba [2] 79 8f [2] 57 8f [2] 68 93 }

  condition:
    any of them
}