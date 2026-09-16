rule TTP_XOR_WriteProcessMemory_cc39 {
  strings:
    $key_cc39 = { 9b 4b [2] a9 69 [2] af 5c [2] 81 5c [2] be 40 }

  condition:
    any of them
}