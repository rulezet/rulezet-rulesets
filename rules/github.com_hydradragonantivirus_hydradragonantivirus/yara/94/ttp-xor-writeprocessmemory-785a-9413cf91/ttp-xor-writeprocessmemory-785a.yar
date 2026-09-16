rule TTP_XOR_WriteProcessMemory_785a {
  strings:
    $key_785a = { 2f 28 [2] 1d 0a [2] 1b 3f [2] 35 3f [2] 0a 23 }

  condition:
    any of them
}