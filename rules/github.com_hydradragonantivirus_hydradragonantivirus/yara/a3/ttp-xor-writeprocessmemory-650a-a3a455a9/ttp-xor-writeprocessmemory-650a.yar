rule TTP_XOR_WriteProcessMemory_650a {
  strings:
    $key_650a = { 32 78 [2] 00 5a [2] 06 6f [2] 28 6f [2] 17 73 }

  condition:
    any of them
}