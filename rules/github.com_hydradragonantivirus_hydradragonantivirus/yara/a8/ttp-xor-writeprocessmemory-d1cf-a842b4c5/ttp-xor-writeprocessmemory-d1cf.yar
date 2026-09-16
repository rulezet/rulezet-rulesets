rule TTP_XOR_WriteProcessMemory_d1cf {
  strings:
    $key_d1cf = { 86 bd [2] b4 9f [2] b2 aa [2] 9c aa [2] a3 b6 }

  condition:
    any of them
}