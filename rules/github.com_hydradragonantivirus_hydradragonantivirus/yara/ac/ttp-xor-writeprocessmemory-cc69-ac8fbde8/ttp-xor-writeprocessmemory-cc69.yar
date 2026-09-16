rule TTP_XOR_WriteProcessMemory_cc69 {
  strings:
    $key_cc69 = { 9b 1b [2] a9 39 [2] af 0c [2] 81 0c [2] be 10 }

  condition:
    any of them
}