rule TTP_XOR_WriteProcessMemory_cc24 {
  strings:
    $key_cc24 = { 9b 56 [2] a9 74 [2] af 41 [2] 81 41 [2] be 5d }

  condition:
    any of them
}