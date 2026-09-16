rule TTP_XOR_WriteProcessMemory_781a {
  strings:
    $key_781a = { 2f 68 [2] 1d 4a [2] 1b 7f [2] 35 7f [2] 0a 63 }

  condition:
    any of them
}