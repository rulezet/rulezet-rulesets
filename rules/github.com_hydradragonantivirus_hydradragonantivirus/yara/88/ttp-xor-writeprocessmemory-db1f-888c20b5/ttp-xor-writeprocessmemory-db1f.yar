rule TTP_XOR_WriteProcessMemory_db1f {
  strings:
    $key_db1f = { 8c 6d [2] be 4f [2] b8 7a [2] 96 7a [2] a9 66 }

  condition:
    any of them
}