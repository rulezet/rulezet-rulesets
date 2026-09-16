rule TTP_XOR_WriteProcessMemory_cc1b {
  strings:
    $key_cc1b = { 9b 69 [2] a9 4b [2] af 7e [2] 81 7e [2] be 62 }

  condition:
    any of them
}