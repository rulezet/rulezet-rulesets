rule TTP_XOR_WriteProcessMemory_335a {
  strings:
    $key_335a = { 64 28 [2] 56 0a [2] 50 3f [2] 7e 3f [2] 41 23 }

  condition:
    any of them
}