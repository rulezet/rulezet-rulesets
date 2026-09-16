rule TTP_XOR_WriteProcessMemory_561a {
  strings:
    $key_561a = { 01 68 [2] 33 4a [2] 35 7f [2] 1b 7f [2] 24 63 }

  condition:
    any of them
}