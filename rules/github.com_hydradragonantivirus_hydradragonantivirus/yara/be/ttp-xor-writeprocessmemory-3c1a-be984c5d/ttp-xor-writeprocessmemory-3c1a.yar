rule TTP_XOR_WriteProcessMemory_3c1a {
  strings:
    $key_3c1a = { 6b 68 [2] 59 4a [2] 5f 7f [2] 71 7f [2] 4e 63 }

  condition:
    any of them
}