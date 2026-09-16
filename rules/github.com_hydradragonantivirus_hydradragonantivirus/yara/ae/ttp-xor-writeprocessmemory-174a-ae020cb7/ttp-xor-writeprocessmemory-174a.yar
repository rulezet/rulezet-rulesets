rule TTP_XOR_WriteProcessMemory_174a {
  strings:
    $key_174a = { 40 38 [2] 72 1a [2] 74 2f [2] 5a 2f [2] 65 33 }

  condition:
    any of them
}