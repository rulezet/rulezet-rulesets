rule TTP_XOR_WriteProcessMemory_277a {
  strings:
    $key_277a = { 70 08 [2] 42 2a [2] 44 1f [2] 6a 1f [2] 55 03 }

  condition:
    any of them
}