rule TTP_XOR_WriteProcessMemory_00cf {
  strings:
    $key_00cf = { 57 bd [2] 65 9f [2] 63 aa [2] 4d aa [2] 72 b6 }

  condition:
    any of them
}