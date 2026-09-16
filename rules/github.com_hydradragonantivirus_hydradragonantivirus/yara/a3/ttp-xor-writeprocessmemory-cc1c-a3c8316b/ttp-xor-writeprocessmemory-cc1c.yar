rule TTP_XOR_WriteProcessMemory_cc1c {
  strings:
    $key_cc1c = { 9b 6e [2] a9 4c [2] af 79 [2] 81 79 [2] be 65 }

  condition:
    any of them
}