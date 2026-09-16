rule TTP_XOR_WriteProcessMemory_045f {
  strings:
    $key_045f = { 53 2d [2] 61 0f [2] 67 3a [2] 49 3a [2] 76 26 }

  condition:
    any of them
}