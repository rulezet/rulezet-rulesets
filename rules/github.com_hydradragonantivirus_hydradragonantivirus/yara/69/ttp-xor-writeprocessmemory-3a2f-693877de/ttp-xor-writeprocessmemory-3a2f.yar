rule TTP_XOR_WriteProcessMemory_3a2f {
  strings:
    $key_3a2f = { 6d 5d [2] 5f 7f [2] 59 4a [2] 77 4a [2] 48 56 }

  condition:
    any of them
}