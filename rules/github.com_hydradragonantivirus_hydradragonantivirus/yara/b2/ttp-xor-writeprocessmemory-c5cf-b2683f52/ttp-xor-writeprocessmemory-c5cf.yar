rule TTP_XOR_WriteProcessMemory_c5cf {
  strings:
    $key_c5cf = { 92 bd [2] a0 9f [2] a6 aa [2] 88 aa [2] b7 b6 }

  condition:
    any of them
}