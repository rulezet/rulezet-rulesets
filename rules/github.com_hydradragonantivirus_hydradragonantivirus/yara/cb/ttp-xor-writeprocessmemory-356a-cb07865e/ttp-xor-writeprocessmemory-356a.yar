rule TTP_XOR_WriteProcessMemory_356a {
  strings:
    $key_356a = { 62 18 [2] 50 3a [2] 56 0f [2] 78 0f [2] 47 13 }

  condition:
    any of them
}