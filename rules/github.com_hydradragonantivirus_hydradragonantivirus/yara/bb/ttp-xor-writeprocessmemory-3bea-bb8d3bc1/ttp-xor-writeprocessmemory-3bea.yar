rule TTP_XOR_WriteProcessMemory_3bea {
  strings:
    $key_3bea = { 6c 98 [2] 5e ba [2] 58 8f [2] 76 8f [2] 49 93 }

  condition:
    any of them
}