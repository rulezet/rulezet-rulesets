rule TTP_XOR_WriteProcessMemory_482a {
  strings:
    $key_482a = { 1f 58 [2] 2d 7a [2] 2b 4f [2] 05 4f [2] 3a 53 }

  condition:
    any of them
}