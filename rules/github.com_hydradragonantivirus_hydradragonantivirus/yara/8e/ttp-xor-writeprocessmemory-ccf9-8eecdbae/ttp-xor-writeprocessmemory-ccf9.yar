rule TTP_XOR_WriteProcessMemory_ccf9 {
  strings:
    $key_ccf9 = { 9b 8b [2] a9 a9 [2] af 9c [2] 81 9c [2] be 80 }

  condition:
    any of them
}