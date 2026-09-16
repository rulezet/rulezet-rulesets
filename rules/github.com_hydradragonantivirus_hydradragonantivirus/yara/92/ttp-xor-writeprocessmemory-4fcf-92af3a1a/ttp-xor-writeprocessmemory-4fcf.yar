rule TTP_XOR_WriteProcessMemory_4fcf {
  strings:
    $key_4fcf = { 18 bd [2] 2a 9f [2] 2c aa [2] 02 aa [2] 3d b6 }

  condition:
    any of them
}