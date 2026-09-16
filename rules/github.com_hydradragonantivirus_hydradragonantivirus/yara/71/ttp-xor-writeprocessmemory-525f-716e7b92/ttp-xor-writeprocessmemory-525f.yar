rule TTP_XOR_WriteProcessMemory_525f {
  strings:
    $key_525f = { 05 2d [2] 37 0f [2] 31 3a [2] 1f 3a [2] 20 26 }

  condition:
    any of them
}