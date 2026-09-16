rule TTP_XOR_WriteProcessMemory_cc7e {
  strings:
    $key_cc7e = { 9b 0c [2] a9 2e [2] af 1b [2] 81 1b [2] be 07 }

  condition:
    any of them
}