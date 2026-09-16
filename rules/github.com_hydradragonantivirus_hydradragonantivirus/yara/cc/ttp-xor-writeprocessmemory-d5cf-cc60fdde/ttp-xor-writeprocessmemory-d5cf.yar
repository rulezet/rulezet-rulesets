rule TTP_XOR_WriteProcessMemory_d5cf {
  strings:
    $key_d5cf = { 82 bd [2] b0 9f [2] b6 aa [2] 98 aa [2] a7 b6 }

  condition:
    any of them
}