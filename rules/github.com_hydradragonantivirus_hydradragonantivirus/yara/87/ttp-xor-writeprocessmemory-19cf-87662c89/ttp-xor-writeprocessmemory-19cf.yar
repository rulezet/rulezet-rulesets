rule TTP_XOR_WriteProcessMemory_19cf {
  strings:
    $key_19cf = { 4e bd [2] 7c 9f [2] 7a aa [2] 54 aa [2] 6b b6 }

  condition:
    any of them
}