rule TTP_XOR_WriteProcessMemory_757a {
  strings:
    $key_757a = { 22 08 [2] 10 2a [2] 16 1f [2] 38 1f [2] 07 03 }

  condition:
    any of them
}