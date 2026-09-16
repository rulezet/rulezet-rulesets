rule TTP_XOR_WriteProcessMemory_437a {
  strings:
    $key_437a = { 14 08 [2] 26 2a [2] 20 1f [2] 0e 1f [2] 31 03 }

  condition:
    any of them
}