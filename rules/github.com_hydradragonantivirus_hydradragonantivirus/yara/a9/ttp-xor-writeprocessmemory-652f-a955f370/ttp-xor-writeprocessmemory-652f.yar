rule TTP_XOR_WriteProcessMemory_652f {
  strings:
    $key_652f = { 32 5d [2] 00 7f [2] 06 4a [2] 28 4a [2] 17 56 }

  condition:
    any of them
}