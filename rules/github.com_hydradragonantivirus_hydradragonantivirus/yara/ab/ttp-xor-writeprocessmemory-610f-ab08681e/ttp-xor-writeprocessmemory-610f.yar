rule TTP_XOR_WriteProcessMemory_610f {
  strings:
    $key_610f = { 36 7d [2] 04 5f [2] 02 6a [2] 2c 6a [2] 13 76 }

  condition:
    any of them
}