rule TTP_XOR_WriteProcessMemory_cc0f {
  strings:
    $key_cc0f = { 9b 7d [2] a9 5f [2] af 6a [2] 81 6a [2] be 76 }

  condition:
    any of them
}