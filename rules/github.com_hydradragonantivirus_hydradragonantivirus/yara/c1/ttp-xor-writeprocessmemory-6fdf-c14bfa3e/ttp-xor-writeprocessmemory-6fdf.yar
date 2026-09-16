rule TTP_XOR_WriteProcessMemory_6fdf {
  strings:
    $key_6fdf = { 38 ad [2] 0a 8f [2] 0c ba [2] 22 ba [2] 1d a6 }

  condition:
    any of them
}