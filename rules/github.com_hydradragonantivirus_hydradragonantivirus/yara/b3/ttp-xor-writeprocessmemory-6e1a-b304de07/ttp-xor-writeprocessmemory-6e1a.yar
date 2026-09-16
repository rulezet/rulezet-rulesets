rule TTP_XOR_WriteProcessMemory_6e1a {
  strings:
    $key_6e1a = { 39 68 [2] 0b 4a [2] 0d 7f [2] 23 7f [2] 1c 63 }

  condition:
    any of them
}