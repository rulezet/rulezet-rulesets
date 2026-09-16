rule TTP_XOR_WriteProcessMemory_2a7a {
  strings:
    $key_2a7a = { 7d 08 [2] 4f 2a [2] 49 1f [2] 67 1f [2] 58 03 }

  condition:
    any of them
}