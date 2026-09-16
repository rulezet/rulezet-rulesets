rule TTP_XOR_WriteProcessMemory_551a {
  strings:
    $key_551a = { 02 68 [2] 30 4a [2] 36 7f [2] 18 7f [2] 27 63 }

  condition:
    any of them
}