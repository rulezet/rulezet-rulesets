rule TTP_XOR_WriteProcessMemory_065f {
  strings:
    $key_065f = { 51 2d [2] 63 0f [2] 65 3a [2] 4b 3a [2] 74 26 }

  condition:
    any of them
}