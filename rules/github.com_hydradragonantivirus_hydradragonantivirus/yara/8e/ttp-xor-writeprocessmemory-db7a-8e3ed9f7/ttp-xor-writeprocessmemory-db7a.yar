rule TTP_XOR_WriteProcessMemory_db7a {
  strings:
    $key_db7a = { 8c 08 [2] be 2a [2] b8 1f [2] 96 1f [2] a9 03 }

  condition:
    any of them
}