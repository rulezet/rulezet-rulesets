rule TTP_XOR_WriteProcessMemory_4cdf {
  strings:
    $key_4cdf = { 1b ad [2] 29 8f [2] 2f ba [2] 01 ba [2] 3e a6 }

  condition:
    any of them
}