rule TTP_XOR_WriteProcessMemory_112f {
  strings:
    $key_112f = { 46 5d [2] 74 7f [2] 72 4a [2] 5c 4a [2] 63 56 }

  condition:
    any of them
}