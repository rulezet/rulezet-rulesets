rule TTP_XOR_WriteProcessMemory_532a {
  strings:
    $key_532a = { 04 58 [2] 36 7a [2] 30 4f [2] 1e 4f [2] 21 53 }

  condition:
    any of them
}