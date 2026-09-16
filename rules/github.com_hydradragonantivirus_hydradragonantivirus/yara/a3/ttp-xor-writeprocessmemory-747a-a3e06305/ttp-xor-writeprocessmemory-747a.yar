rule TTP_XOR_WriteProcessMemory_747a {
  strings:
    $key_747a = { 23 08 [2] 11 2a [2] 17 1f [2] 39 1f [2] 06 03 }

  condition:
    any of them
}