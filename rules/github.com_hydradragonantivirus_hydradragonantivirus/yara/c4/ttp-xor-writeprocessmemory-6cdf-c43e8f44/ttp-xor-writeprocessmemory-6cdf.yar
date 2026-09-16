rule TTP_XOR_WriteProcessMemory_6cdf {
  strings:
    $key_6cdf = { 3b ad [2] 09 8f [2] 0f ba [2] 21 ba [2] 1e a6 }

  condition:
    any of them
}