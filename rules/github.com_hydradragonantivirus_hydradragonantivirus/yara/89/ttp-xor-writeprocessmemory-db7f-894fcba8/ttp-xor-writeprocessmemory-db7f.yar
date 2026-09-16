rule TTP_XOR_WriteProcessMemory_db7f {
  strings:
    $key_db7f = { 8c 0d [2] be 2f [2] b8 1a [2] 96 1a [2] a9 06 }

  condition:
    any of them
}