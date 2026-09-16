rule TTP_XOR_WriteProcessMemory_717a {
  strings:
    $key_717a = { 26 08 [2] 14 2a [2] 12 1f [2] 3c 1f [2] 03 03 }

  condition:
    any of them
}