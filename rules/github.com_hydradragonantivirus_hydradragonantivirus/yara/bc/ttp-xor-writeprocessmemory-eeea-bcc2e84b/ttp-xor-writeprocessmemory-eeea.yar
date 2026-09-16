rule TTP_XOR_WriteProcessMemory_eeea {
  strings:
    $key_eeea = { b9 98 [2] 8b ba [2] 8d 8f [2] a3 8f [2] 9c 93 }

  condition:
    any of them
}