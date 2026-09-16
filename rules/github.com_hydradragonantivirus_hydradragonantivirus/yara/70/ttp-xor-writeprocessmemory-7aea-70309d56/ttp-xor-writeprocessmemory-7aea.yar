rule TTP_XOR_WriteProcessMemory_7aea {
  strings:
    $key_7aea = { 2d 98 [2] 1f ba [2] 19 8f [2] 37 8f [2] 08 93 }

  condition:
    any of them
}