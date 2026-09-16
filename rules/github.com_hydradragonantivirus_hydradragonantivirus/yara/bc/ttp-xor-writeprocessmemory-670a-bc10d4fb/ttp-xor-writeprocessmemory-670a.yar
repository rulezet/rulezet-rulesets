rule TTP_XOR_WriteProcessMemory_670a {
  strings:
    $key_670a = { 30 78 [2] 02 5a [2] 04 6f [2] 2a 6f [2] 15 73 }

  condition:
    any of them
}