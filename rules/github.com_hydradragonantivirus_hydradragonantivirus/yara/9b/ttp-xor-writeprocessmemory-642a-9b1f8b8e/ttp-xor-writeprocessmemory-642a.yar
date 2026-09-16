rule TTP_XOR_WriteProcessMemory_642a {
  strings:
    $key_642a = { 33 58 [2] 01 7a [2] 07 4f [2] 29 4f [2] 16 53 }

  condition:
    any of them
}