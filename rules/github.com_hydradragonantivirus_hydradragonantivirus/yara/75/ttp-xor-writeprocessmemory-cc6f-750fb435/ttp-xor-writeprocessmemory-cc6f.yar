rule TTP_XOR_WriteProcessMemory_cc6f {
  strings:
    $key_cc6f = { 9b 1d [2] a9 3f [2] af 0a [2] 81 0a [2] be 16 }

  condition:
    any of them
}