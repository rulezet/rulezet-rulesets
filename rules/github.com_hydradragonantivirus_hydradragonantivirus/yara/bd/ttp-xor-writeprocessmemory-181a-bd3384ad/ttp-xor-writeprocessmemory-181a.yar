rule TTP_XOR_WriteProcessMemory_181a {
  strings:
    $key_181a = { 4f 68 [2] 7d 4a [2] 7b 7f [2] 55 7f [2] 6a 63 }

  condition:
    any of them
}