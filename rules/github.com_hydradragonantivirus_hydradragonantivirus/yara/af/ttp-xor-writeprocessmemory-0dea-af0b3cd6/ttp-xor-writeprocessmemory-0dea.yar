rule TTP_XOR_WriteProcessMemory_0dea {
  strings:
    $key_0dea = { 5a 98 [2] 68 ba [2] 6e 8f [2] 40 8f [2] 7f 93 }

  condition:
    any of them
}