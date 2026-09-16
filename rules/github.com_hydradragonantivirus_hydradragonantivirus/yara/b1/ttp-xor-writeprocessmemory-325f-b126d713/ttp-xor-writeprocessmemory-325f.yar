rule TTP_XOR_WriteProcessMemory_325f {
  strings:
    $key_325f = { 65 2d [2] 57 0f [2] 51 3a [2] 7f 3a [2] 40 26 }

  condition:
    any of them
}