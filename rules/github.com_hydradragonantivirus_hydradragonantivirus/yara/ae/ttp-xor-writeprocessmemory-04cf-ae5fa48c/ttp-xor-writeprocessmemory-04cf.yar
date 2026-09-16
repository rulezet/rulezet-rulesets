rule TTP_XOR_WriteProcessMemory_04cf {
  strings:
    $key_04cf = { 53 bd [2] 61 9f [2] 67 aa [2] 49 aa [2] 76 b6 }

  condition:
    any of them
}