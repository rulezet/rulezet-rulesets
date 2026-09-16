rule TTP_XOR_WriteProcessMemory_667a {
  strings:
    $key_667a = { 31 08 [2] 03 2a [2] 05 1f [2] 2b 1f [2] 14 03 }

  condition:
    any of them
}