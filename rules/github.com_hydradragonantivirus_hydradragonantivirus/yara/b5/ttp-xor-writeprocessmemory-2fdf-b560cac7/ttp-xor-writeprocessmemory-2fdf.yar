rule TTP_XOR_WriteProcessMemory_2fdf {
  strings:
    $key_2fdf = { 78 ad [2] 4a 8f [2] 4c ba [2] 62 ba [2] 5d a6 }

  condition:
    any of them
}