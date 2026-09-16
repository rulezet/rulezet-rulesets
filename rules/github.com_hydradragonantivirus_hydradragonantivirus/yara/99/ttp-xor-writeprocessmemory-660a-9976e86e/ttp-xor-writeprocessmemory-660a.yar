rule TTP_XOR_WriteProcessMemory_660a {
  strings:
    $key_660a = { 31 78 [2] 03 5a [2] 05 6f [2] 2b 6f [2] 14 73 }

  condition:
    any of them
}