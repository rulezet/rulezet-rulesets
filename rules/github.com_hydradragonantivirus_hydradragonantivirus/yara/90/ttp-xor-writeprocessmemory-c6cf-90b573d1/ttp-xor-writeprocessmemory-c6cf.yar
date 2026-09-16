rule TTP_XOR_WriteProcessMemory_c6cf {
  strings:
    $key_c6cf = { 91 bd [2] a3 9f [2] a5 aa [2] 8b aa [2] b4 b6 }

  condition:
    any of them
}