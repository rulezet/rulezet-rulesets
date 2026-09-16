rule TTP_XOR_WriteProcessMemory_e3cf {
  strings:
    $key_e3cf = { b4 bd [2] 86 9f [2] 80 aa [2] ae aa [2] 91 b6 }

  condition:
    any of them
}