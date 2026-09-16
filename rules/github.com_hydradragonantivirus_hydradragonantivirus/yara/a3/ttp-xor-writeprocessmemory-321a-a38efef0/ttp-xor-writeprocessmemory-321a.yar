rule TTP_XOR_WriteProcessMemory_321a {
  strings:
    $key_321a = { 65 68 [2] 57 4a [2] 51 7f [2] 7f 7f [2] 40 63 }

  condition:
    any of them
}