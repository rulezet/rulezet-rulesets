rule TTP_XOR_WriteProcessMemory_402f {
  strings:
    $key_402f = { 17 5d [2] 25 7f [2] 23 4a [2] 0d 4a [2] 32 56 }

  condition:
    any of them
}