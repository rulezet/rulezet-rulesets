rule TTP_XOR_WriteProcessMemory_cc7d {
  strings:
    $key_cc7d = { 9b 0f [2] a9 2d [2] af 18 [2] 81 18 [2] be 04 }

  condition:
    any of them
}