rule TTP_XOR_WriteProcessMemory_06cf {
  strings:
    $key_06cf = { 51 bd [2] 63 9f [2] 65 aa [2] 4b aa [2] 74 b6 }

  condition:
    any of them
}