rule TTP_XOR_WriteProcessMemory_663f {
  strings:
    $key_663f = { 31 4d [2] 03 6f [2] 05 5a [2] 2b 5a [2] 14 46 }

  condition:
    any of them
}