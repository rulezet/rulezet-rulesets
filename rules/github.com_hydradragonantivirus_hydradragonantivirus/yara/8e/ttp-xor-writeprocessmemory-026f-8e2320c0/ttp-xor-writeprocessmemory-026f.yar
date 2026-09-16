rule TTP_XOR_WriteProcessMemory_026f {
  strings:
    $key_026f = { 55 1d [2] 67 3f [2] 61 0a [2] 4f 0a [2] 70 16 }

  condition:
    any of them
}