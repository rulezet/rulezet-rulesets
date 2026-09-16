rule TTP_XOR_WriteProcessMemory_1fcf {
  strings:
    $key_1fcf = { 48 bd [2] 7a 9f [2] 7c aa [2] 52 aa [2] 6d b6 }

  condition:
    any of them
}