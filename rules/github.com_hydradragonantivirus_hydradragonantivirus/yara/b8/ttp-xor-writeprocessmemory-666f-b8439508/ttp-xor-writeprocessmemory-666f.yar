rule TTP_XOR_WriteProcessMemory_666f {
  strings:
    $key_666f = { 31 1d [2] 03 3f [2] 05 0a [2] 2b 0a [2] 14 16 }

  condition:
    any of them
}