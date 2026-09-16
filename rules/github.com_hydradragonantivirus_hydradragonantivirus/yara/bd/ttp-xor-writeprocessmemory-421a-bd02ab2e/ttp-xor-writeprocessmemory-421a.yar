rule TTP_XOR_WriteProcessMemory_421a {
  strings:
    $key_421a = { 15 68 [2] 27 4a [2] 21 7f [2] 0f 7f [2] 30 63 }

  condition:
    any of them
}