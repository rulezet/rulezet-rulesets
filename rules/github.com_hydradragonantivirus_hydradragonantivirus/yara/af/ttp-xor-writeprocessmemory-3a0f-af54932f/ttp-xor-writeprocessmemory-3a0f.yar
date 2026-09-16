rule TTP_XOR_WriteProcessMemory_3a0f {
  strings:
    $key_3a0f = { 6d 7d [2] 5f 5f [2] 59 6a [2] 77 6a [2] 48 76 }

  condition:
    any of them
}