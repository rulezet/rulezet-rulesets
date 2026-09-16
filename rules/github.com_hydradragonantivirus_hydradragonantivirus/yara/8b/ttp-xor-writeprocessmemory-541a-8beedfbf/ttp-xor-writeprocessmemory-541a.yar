rule TTP_XOR_WriteProcessMemory_541a {
  strings:
    $key_541a = { 03 68 [2] 31 4a [2] 37 7f [2] 19 7f [2] 26 63 }

  condition:
    any of them
}