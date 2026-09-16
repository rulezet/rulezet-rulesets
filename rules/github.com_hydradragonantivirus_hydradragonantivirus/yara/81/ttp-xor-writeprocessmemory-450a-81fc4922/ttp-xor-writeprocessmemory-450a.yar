rule TTP_XOR_WriteProcessMemory_450a {
  strings:
    $key_450a = { 12 78 [2] 20 5a [2] 26 6f [2] 08 6f [2] 37 73 }

  condition:
    any of them
}