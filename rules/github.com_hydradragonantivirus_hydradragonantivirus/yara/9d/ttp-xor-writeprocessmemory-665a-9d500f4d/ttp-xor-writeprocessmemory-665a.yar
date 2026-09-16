rule TTP_XOR_WriteProcessMemory_665a {
  strings:
    $key_665a = { 31 28 [2] 03 0a [2] 05 3f [2] 2b 3f [2] 14 23 }

  condition:
    any of them
}