rule TTP_XOR_WriteProcessMemory_6adf {
  strings:
    $key_6adf = { 3d ad [2] 0f 8f [2] 09 ba [2] 27 ba [2] 18 a6 }

  condition:
    any of them
}