rule TTP_XOR_WriteProcessMemory_2a1f {
  strings:
    $key_2a1f = { 7d 6d [2] 4f 4f [2] 49 7a [2] 67 7a [2] 58 66 }

  condition:
    any of them
}