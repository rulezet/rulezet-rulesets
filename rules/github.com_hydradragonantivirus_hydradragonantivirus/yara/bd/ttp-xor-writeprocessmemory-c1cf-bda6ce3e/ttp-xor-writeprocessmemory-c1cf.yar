rule TTP_XOR_WriteProcessMemory_c1cf {
  strings:
    $key_c1cf = { 96 bd [2] a4 9f [2] a2 aa [2] 8c aa [2] b3 b6 }

  condition:
    any of them
}