rule TTP_XOR_WriteProcessMemory_071a {
  strings:
    $key_071a = { 50 68 [2] 62 4a [2] 64 7f [2] 4a 7f [2] 75 63 }

  condition:
    any of them
}