rule TTP_XOR_WriteProcessMemory_3cdf {
  strings:
    $key_3cdf = { 6b ad [2] 59 8f [2] 5f ba [2] 71 ba [2] 4e a6 }

  condition:
    any of them
}