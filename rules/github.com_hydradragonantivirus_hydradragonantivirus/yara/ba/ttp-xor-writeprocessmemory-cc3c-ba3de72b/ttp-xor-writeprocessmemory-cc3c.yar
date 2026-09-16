rule TTP_XOR_WriteProcessMemory_cc3c {
  strings:
    $key_cc3c = { 9b 4e [2] a9 6c [2] af 59 [2] 81 59 [2] be 45 }

  condition:
    any of them
}