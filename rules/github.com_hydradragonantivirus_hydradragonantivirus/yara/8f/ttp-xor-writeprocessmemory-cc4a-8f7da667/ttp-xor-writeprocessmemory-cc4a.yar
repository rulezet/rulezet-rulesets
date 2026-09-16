rule TTP_XOR_WriteProcessMemory_cc4a {
  strings:
    $key_cc4a = { 9b 38 [2] a9 1a [2] af 2f [2] 81 2f [2] be 33 }

  condition:
    any of them
}