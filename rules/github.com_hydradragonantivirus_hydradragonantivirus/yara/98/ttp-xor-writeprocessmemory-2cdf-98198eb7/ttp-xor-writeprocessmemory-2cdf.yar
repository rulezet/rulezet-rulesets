rule TTP_XOR_WriteProcessMemory_2cdf {
  strings:
    $key_2cdf = { 7b ad [2] 49 8f [2] 4f ba [2] 61 ba [2] 5e a6 }

  condition:
    any of them
}