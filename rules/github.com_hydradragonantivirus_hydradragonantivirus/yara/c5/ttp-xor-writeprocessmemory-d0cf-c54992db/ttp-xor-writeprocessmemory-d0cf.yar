rule TTP_XOR_WriteProcessMemory_d0cf {
  strings:
    $key_d0cf = { 87 bd [2] b5 9f [2] b3 aa [2] 9d aa [2] a2 b6 }

  condition:
    any of them
}