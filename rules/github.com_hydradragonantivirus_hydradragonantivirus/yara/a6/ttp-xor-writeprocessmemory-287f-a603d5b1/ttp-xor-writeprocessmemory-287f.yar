rule TTP_XOR_WriteProcessMemory_287f {
  strings:
    $key_287f = { 7f 0d [2] 4d 2f [2] 4b 1a [2] 65 1a [2] 5a 06 }

  condition:
    any of them
}