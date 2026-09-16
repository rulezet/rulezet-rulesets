rule TTP_XOR_WriteProcessMemory_227a {
  strings:
    $key_227a = { 75 08 [2] 47 2a [2] 41 1f [2] 6f 1f [2] 50 03 }

  condition:
    any of them
}