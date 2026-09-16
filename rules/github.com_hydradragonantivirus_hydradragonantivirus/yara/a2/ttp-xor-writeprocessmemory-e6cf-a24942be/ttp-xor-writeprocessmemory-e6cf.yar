rule TTP_XOR_WriteProcessMemory_e6cf {
  strings:
    $key_e6cf = { b1 bd [2] 83 9f [2] 85 aa [2] ab aa [2] 94 b6 }

  condition:
    any of them
}