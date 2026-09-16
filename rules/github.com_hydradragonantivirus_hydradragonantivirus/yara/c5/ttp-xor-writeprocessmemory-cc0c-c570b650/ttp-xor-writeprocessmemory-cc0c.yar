rule TTP_XOR_WriteProcessMemory_cc0c {
  strings:
    $key_cc0c = { 9b 7e [2] a9 5c [2] af 69 [2] 81 69 [2] be 75 }

  condition:
    any of them
}