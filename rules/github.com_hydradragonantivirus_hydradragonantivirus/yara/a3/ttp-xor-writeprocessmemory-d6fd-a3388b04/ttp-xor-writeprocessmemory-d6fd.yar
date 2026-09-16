rule TTP_XOR_WriteProcessMemory_d6fd {
  strings:
    $key_d6fd = { 81 8f [2] b3 ad [2] b5 98 [2] 9b 98 [2] a4 84 }

  condition:
    any of them
}