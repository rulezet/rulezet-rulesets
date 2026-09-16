rule TTP_XOR_WriteProcessMemory_087f {
  strings:
    $key_087f = { 5f 0d [2] 6d 2f [2] 6b 1a [2] 45 1a [2] 7a 06 }

  condition:
    any of them
}