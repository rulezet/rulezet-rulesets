rule TTP_XOR_WriteProcessMemory_326a {
  strings:
    $key_326a = { 65 18 [2] 57 3a [2] 51 0f [2] 7f 0f [2] 40 13 }

  condition:
    any of them
}