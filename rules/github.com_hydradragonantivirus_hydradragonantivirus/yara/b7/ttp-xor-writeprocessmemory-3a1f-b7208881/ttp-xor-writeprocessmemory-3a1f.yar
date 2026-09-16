rule TTP_XOR_WriteProcessMemory_3a1f {
  strings:
    $key_3a1f = { 6d 6d [2] 5f 4f [2] 59 7a [2] 77 7a [2] 48 66 }

  condition:
    any of them
}