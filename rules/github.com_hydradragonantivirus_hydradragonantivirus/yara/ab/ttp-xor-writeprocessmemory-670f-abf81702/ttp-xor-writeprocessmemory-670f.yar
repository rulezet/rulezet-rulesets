rule TTP_XOR_WriteProcessMemory_670f {
  strings:
    $key_670f = { 30 7d [2] 02 5f [2] 04 6a [2] 2a 6a [2] 15 76 }

  condition:
    any of them
}