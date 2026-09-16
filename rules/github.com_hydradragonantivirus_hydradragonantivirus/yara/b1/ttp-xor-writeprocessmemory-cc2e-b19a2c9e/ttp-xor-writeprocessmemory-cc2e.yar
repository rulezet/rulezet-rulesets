rule TTP_XOR_WriteProcessMemory_cc2e {
  strings:
    $key_cc2e = { 9b 5c [2] a9 7e [2] af 4b [2] 81 4b [2] be 57 }

  condition:
    any of them
}