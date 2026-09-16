rule TTP_XOR_WriteProcessMemory_532f {
  strings:
    $key_532f = { 04 5d [2] 36 7f [2] 30 4a [2] 1e 4a [2] 21 56 }

  condition:
    any of them
}