rule TTP_XOR_WriteProcessMemory_423f {
  strings:
    $key_423f = { 15 4d [2] 27 6f [2] 21 5a [2] 0f 5a [2] 30 46 }

  condition:
    any of them
}