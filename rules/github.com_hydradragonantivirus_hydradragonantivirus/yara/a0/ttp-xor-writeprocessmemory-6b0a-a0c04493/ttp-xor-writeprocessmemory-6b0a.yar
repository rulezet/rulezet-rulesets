rule TTP_XOR_WriteProcessMemory_6b0a {
  strings:
    $key_6b0a = { 3c 78 [2] 0e 5a [2] 08 6f [2] 26 6f [2] 19 73 }

  condition:
    any of them
}