rule TTP_XOR_WriteProcessMemory_187a {
  strings:
    $key_187a = { 4f 08 [2] 7d 2a [2] 7b 1f [2] 55 1f [2] 6a 03 }

  condition:
    any of them
}