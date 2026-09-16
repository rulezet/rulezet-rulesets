rule TTP_XOR_WriteProcessMemory_db1a {
  strings:
    $key_db1a = { 8c 68 [2] be 4a [2] b8 7f [2] 96 7f [2] a9 63 }

  condition:
    any of them
}