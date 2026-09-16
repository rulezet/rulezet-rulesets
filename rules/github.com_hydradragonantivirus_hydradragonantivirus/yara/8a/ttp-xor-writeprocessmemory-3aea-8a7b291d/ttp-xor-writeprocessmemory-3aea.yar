rule TTP_XOR_WriteProcessMemory_3aea {
  strings:
    $key_3aea = { 6d 98 [2] 5f ba [2] 59 8f [2] 77 8f [2] 48 93 }

  condition:
    any of them
}