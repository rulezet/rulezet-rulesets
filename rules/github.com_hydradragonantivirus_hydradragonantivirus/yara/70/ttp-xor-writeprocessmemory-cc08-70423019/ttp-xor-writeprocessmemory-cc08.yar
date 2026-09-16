rule TTP_XOR_WriteProcessMemory_cc08 {
  strings:
    $key_cc08 = { 9b 7a [2] a9 58 [2] af 6d [2] 81 6d [2] be 71 }

  condition:
    any of them
}