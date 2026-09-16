rule TTP_XOR_WriteProcessMemory_670d {
  strings:
    $key_670d = { 30 7f [2] 02 5d [2] 04 68 [2] 2a 68 [2] 15 74 }

  condition:
    any of them
}