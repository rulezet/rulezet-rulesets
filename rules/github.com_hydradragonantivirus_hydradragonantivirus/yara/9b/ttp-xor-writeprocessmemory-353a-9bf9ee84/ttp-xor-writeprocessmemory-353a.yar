rule TTP_XOR_WriteProcessMemory_353a {
  strings:
    $key_353a = { 62 48 [2] 50 6a [2] 56 5f [2] 78 5f [2] 47 43 }

  condition:
    any of them
}