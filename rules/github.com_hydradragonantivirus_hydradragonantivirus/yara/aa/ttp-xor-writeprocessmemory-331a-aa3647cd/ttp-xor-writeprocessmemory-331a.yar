rule TTP_XOR_WriteProcessMemory_331a {
  strings:
    $key_331a = { 64 68 [2] 56 4a [2] 50 7f [2] 7e 7f [2] 41 63 }

  condition:
    any of them
}