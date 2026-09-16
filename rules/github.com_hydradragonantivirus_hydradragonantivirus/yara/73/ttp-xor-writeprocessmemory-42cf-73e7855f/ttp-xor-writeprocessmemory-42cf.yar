rule TTP_XOR_WriteProcessMemory_42cf {
  strings:
    $key_42cf = { 15 bd [2] 27 9f [2] 21 aa [2] 0f aa [2] 30 b6 }

  condition:
    any of them
}