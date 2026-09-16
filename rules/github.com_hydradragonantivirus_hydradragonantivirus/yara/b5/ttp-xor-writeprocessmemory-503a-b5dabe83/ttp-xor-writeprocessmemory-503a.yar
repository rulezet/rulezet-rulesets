rule TTP_XOR_WriteProcessMemory_503a {
  strings:
    $key_503a = { 07 48 [2] 35 6a [2] 33 5f [2] 1d 5f [2] 22 43 }

  condition:
    any of them
}