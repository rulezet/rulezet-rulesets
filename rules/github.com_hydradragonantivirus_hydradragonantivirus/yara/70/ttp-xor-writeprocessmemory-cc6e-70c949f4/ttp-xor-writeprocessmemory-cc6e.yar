rule TTP_XOR_WriteProcessMemory_cc6e {
  strings:
    $key_cc6e = { 9b 1c [2] a9 3e [2] af 0b [2] 81 0b [2] be 17 }

  condition:
    any of them
}