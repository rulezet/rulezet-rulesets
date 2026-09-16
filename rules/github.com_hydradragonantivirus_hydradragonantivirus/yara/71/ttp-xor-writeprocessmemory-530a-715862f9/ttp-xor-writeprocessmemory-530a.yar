rule TTP_XOR_WriteProcessMemory_530a {
  strings:
    $key_530a = { 04 78 [2] 36 5a [2] 30 6f [2] 1e 6f [2] 21 73 }

  condition:
    any of them
}