rule TTP_XOR_WriteProcessMemory_333a {
  strings:
    $key_333a = { 64 48 [2] 56 6a [2] 50 5f [2] 7e 5f [2] 41 43 }

  condition:
    any of them
}