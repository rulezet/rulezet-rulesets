rule TTP_XOR_WriteProcessMemory_db0a {
  strings:
    $key_db0a = { 8c 78 [2] be 5a [2] b8 6f [2] 96 6f [2] a9 73 }

  condition:
    any of them
}