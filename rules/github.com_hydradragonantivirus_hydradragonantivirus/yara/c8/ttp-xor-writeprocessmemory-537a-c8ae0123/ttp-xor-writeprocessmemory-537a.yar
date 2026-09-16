rule TTP_XOR_WriteProcessMemory_537a {
  strings:
    $key_537a = { 04 08 [2] 36 2a [2] 30 1f [2] 1e 1f [2] 21 03 }

  condition:
    any of them
}