rule TTP_XOR_WriteProcessMemory_2bea {
  strings:
    $key_2bea = { 7c 98 [2] 4e ba [2] 48 8f [2] 66 8f [2] 59 93 }

  condition:
    any of them
}