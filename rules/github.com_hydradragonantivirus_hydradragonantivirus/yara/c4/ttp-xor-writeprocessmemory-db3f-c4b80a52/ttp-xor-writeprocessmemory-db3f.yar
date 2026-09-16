rule TTP_XOR_WriteProcessMemory_db3f {
  strings:
    $key_db3f = { 8c 4d [2] be 6f [2] b8 5a [2] 96 5a [2] a9 46 }

  condition:
    any of them
}