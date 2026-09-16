rule TTP_XOR_WriteProcessMemory_6fcf {
  strings:
    $key_6fcf = { 38 bd [2] 0a 9f [2] 0c aa [2] 22 aa [2] 1d b6 }

  condition:
    any of them
}