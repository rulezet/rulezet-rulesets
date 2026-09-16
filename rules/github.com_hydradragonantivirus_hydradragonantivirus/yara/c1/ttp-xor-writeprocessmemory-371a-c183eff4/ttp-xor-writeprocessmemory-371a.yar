rule TTP_XOR_WriteProcessMemory_371a {
  strings:
    $key_371a = { 60 68 [2] 52 4a [2] 54 7f [2] 7a 7f [2] 45 63 }

  condition:
    any of them
}