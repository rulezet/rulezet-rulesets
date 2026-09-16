rule TTP_XOR_WriteProcessMemory_3fdf {
  strings:
    $key_3fdf = { 68 ad [2] 5a 8f [2] 5c ba [2] 72 ba [2] 4d a6 }

  condition:
    any of them
}