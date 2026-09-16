rule TTP_XOR_WriteProcessMemory_cc2d {
  strings:
    $key_cc2d = { 9b 5f [2] a9 7d [2] af 48 [2] 81 48 [2] be 54 }

  condition:
    any of them
}