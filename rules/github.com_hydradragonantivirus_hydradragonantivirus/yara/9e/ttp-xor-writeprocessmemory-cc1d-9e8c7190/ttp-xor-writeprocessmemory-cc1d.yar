rule TTP_XOR_WriteProcessMemory_cc1d {
  strings:
    $key_cc1d = { 9b 6f [2] a9 4d [2] af 78 [2] 81 78 [2] be 64 }

  condition:
    any of them
}