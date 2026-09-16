rule TTP_XOR_WriteProcessMemory_cc3e {
  strings:
    $key_cc3e = { 9b 4c [2] a9 6e [2] af 5b [2] 81 5b [2] be 47 }

  condition:
    any of them
}