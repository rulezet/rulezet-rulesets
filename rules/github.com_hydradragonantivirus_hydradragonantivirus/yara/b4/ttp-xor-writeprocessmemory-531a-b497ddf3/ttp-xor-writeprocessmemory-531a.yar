rule TTP_XOR_WriteProcessMemory_531a {
  strings:
    $key_531a = { 04 68 [2] 36 4a [2] 30 7f [2] 1e 7f [2] 21 63 }

  condition:
    any of them
}