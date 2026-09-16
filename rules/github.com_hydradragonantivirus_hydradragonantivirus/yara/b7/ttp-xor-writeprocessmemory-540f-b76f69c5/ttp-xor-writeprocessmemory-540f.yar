rule TTP_XOR_WriteProcessMemory_540f {
  strings:
    $key_540f = { 03 7d [2] 31 5f [2] 37 6a [2] 19 6a [2] 26 76 }

  condition:
    any of them
}