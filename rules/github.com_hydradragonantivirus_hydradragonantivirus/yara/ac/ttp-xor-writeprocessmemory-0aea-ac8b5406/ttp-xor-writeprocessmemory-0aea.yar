rule TTP_XOR_WriteProcessMemory_0aea {
  strings:
    $key_0aea = { 5d 98 [2] 6f ba [2] 69 8f [2] 47 8f [2] 78 93 }

  condition:
    any of them
}