rule TTP_XOR_WriteProcessMemory_59ea {
  strings:
    $key_59ea = { 0e 98 [2] 3c ba [2] 3a 8f [2] 14 8f [2] 2b 93 }

  condition:
    any of them
}