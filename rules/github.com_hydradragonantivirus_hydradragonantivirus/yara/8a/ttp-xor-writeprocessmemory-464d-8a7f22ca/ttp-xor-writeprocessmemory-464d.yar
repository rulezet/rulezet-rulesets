rule TTP_XOR_WriteProcessMemory_464d {
  strings:
    $key_464d = { 11 3f [2] 23 1d [2] 25 28 [2] 0b 28 [2] 34 34 }

  condition:
    any of them
}