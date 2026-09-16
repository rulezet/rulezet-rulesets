rule TTP_XOR_WriteProcessMemory_6bea {
  strings:
    $key_6bea = { 3c 98 [2] 0e ba [2] 08 8f [2] 26 8f [2] 19 93 }

  condition:
    any of them
}