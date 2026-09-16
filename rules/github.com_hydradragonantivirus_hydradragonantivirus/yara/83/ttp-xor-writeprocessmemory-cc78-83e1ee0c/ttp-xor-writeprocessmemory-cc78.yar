rule TTP_XOR_WriteProcessMemory_cc78 {
  strings:
    $key_cc78 = { 9b 0a [2] a9 28 [2] af 1d [2] 81 1d [2] be 01 }

  condition:
    any of them
}