rule TTP_XOR_WriteProcessMemory_281f {
  strings:
    $key_281f = { 7f 6d [2] 4d 4f [2] 4b 7a [2] 65 7a [2] 5a 66 }

  condition:
    any of them
}