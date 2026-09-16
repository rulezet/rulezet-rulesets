rule TTP_XOR_WriteProcessMemory_497a {
  strings:
    $key_497a = { 1e 08 [2] 2c 2a [2] 2a 1f [2] 04 1f [2] 3b 03 }

  condition:
    any of them
}