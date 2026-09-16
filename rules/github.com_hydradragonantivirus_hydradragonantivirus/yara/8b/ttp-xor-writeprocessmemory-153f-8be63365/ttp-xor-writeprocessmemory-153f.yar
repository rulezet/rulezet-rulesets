rule TTP_XOR_WriteProcessMemory_153f {
  strings:
    $key_153f = { 42 4d [2] 70 6f [2] 76 5a [2] 58 5a [2] 67 46 }

  condition:
    any of them
}