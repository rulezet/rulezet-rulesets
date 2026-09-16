rule TTP_XOR_WriteProcessMemory_5bea {
  strings:
    $key_5bea = { 0c 98 [2] 3e ba [2] 38 8f [2] 16 8f [2] 29 93 }

  condition:
    any of them
}