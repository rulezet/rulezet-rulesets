rule TTP_XOR_WriteProcessMemory_cddf {
  strings:
    $key_cddf = { 9a ad [2] a8 8f [2] ae ba [2] 80 ba [2] bf a6 }

  condition:
    any of them
}