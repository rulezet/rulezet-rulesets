rule TTP_XOR_WriteProcessMemory_785f {
  strings:
    $key_785f = { 2f 2d [2] 1d 0f [2] 1b 3a [2] 35 3a [2] 0a 26 }

  condition:
    any of them
}