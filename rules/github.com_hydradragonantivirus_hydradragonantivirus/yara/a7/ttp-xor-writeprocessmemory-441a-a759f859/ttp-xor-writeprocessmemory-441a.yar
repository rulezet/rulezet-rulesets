rule TTP_XOR_WriteProcessMemory_441a {
  strings:
    $key_441a = { 13 68 [2] 21 4a [2] 27 7f [2] 09 7f [2] 36 63 }

  condition:
    any of them
}