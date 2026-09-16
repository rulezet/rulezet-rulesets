rule TTP_XOR_WriteProcessMemory_ccf8 {
  strings:
    $key_ccf8 = { 9b 8a [2] a9 a8 [2] af 9d [2] 81 9d [2] be 81 }

  condition:
    any of them
}