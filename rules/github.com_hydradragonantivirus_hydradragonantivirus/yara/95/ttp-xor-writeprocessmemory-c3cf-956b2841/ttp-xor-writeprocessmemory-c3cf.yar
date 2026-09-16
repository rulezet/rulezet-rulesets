rule TTP_XOR_WriteProcessMemory_c3cf {
  strings:
    $key_c3cf = { 94 bd [2] a6 9f [2] a0 aa [2] 8e aa [2] b1 b6 }

  condition:
    any of them
}