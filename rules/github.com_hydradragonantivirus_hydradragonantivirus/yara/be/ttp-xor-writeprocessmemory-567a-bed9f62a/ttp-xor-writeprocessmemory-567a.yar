rule TTP_XOR_WriteProcessMemory_567a {
  strings:
    $key_567a = { 01 08 [2] 33 2a [2] 35 1f [2] 1b 1f [2] 24 03 }

  condition:
    any of them
}