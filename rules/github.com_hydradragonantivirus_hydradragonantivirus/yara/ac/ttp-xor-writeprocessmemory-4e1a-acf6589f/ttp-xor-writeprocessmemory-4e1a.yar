rule TTP_XOR_WriteProcessMemory_4e1a {
  strings:
    $key_4e1a = { 19 68 [2] 2b 4a [2] 2d 7f [2] 03 7f [2] 3c 63 }

  condition:
    any of them
}