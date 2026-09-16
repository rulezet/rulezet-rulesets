rule TTP_XOR_WriteProcessMemory_464f {
  strings:
    $key_464f = { 11 3d [2] 23 1f [2] 25 2a [2] 0b 2a [2] 34 36 }

  condition:
    any of them
}