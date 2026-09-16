rule TTP_XOR_WriteProcessMemory_c2cf {
  strings:
    $key_c2cf = { 95 bd [2] a7 9f [2] a1 aa [2] 8f aa [2] b0 b6 }

  condition:
    any of them
}