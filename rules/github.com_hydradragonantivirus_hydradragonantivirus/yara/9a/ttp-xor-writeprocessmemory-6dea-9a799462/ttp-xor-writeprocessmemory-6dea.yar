rule TTP_XOR_WriteProcessMemory_6dea {
  strings:
    $key_6dea = { 3a 98 [2] 08 ba [2] 0e 8f [2] 20 8f [2] 1f 93 }

  condition:
    any of them
}