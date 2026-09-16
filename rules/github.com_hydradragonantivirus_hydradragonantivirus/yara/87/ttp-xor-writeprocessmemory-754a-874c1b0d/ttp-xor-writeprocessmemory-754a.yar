rule TTP_XOR_WriteProcessMemory_754a {
  strings:
    $key_754a = { 22 38 [2] 10 1a [2] 16 2f [2] 38 2f [2] 07 33 }

  condition:
    any of them
}