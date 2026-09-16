rule TTP_XOR_WriteProcessMemory_433f {
  strings:
    $key_433f = { 14 4d [2] 26 6f [2] 20 5a [2] 0e 5a [2] 31 46 }

  condition:
    any of them
}