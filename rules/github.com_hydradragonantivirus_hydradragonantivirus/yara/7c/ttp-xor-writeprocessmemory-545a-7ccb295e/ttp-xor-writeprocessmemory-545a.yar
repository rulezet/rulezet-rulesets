rule TTP_XOR_WriteProcessMemory_545a {
  strings:
    $key_545a = { 03 28 [2] 31 0a [2] 37 3f [2] 19 3f [2] 26 23 }

  condition:
    any of them
}