rule TTP_XOR_WriteProcessMemory_713f {
  strings:
    $key_713f = { 26 4d [2] 14 6f [2] 12 5a [2] 3c 5a [2] 03 46 }

  condition:
    any of them
}