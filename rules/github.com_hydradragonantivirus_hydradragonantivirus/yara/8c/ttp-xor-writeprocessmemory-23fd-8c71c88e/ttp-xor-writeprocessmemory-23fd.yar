rule TTP_XOR_WriteProcessMemory_23fd {
  strings:
    $key_23fd = { 74 8f [2] 46 ad [2] 40 98 [2] 6e 98 [2] 51 84 }

  condition:
    any of them
}