rule TTP_XOR_WriteProcessMemory_cc3f {
  strings:
    $key_cc3f = { 9b 4d [2] a9 6f [2] af 5a [2] 81 5a [2] be 46 }

  condition:
    any of them
}