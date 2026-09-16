rule TTP_XOR_WriteProcessMemory_cc2c {
  strings:
    $key_cc2c = { 9b 5e [2] a9 7c [2] af 49 [2] 81 49 [2] be 55 }

  condition:
    any of them
}