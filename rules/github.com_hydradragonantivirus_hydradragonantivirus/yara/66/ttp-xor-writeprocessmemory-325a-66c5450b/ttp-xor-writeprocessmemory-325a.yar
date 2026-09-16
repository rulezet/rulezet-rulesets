rule TTP_XOR_WriteProcessMemory_325a {
  strings:
    $key_325a = { 65 28 [2] 57 0a [2] 51 3f [2] 7f 3f [2] 40 23 }

  condition:
    any of them
}