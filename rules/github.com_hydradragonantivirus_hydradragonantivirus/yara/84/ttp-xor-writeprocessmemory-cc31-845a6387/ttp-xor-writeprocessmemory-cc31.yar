rule TTP_XOR_WriteProcessMemory_cc31 {
  strings:
    $key_cc31 = { 9b 43 [2] a9 61 [2] af 54 [2] 81 54 [2] be 48 }

  condition:
    any of them
}