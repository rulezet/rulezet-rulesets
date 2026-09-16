rule TTP_XOR_WriteProcessMemory_1b1a {
  strings:
    $key_1b1a = { 4c 68 [2] 7e 4a [2] 78 7f [2] 56 7f [2] 69 63 }

  condition:
    any of them
}