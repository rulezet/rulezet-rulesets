rule TTP_XOR_WriteProcessMemory_52cf {
  strings:
    $key_52cf = { 05 bd [2] 37 9f [2] 31 aa [2] 1f aa [2] 20 b6 }

  condition:
    any of them
}