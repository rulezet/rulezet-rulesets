rule TTP_XOR_WriteProcessMemory_f5cf {
  strings:
    $key_f5cf = { a2 bd [2] 90 9f [2] 96 aa [2] b8 aa [2] 87 b6 }

  condition:
    any of them
}