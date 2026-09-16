rule TTP_XOR_WriteProcessMemory_09cf {
  strings:
    $key_09cf = { 5e bd [2] 6c 9f [2] 6a aa [2] 44 aa [2] 7b b6 }

  condition:
    any of them
}