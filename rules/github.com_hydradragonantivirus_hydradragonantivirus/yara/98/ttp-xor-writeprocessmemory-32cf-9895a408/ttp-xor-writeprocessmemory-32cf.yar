rule TTP_XOR_WriteProcessMemory_32cf {
  strings:
    $key_32cf = { 65 bd [2] 57 9f [2] 51 aa [2] 7f aa [2] 40 b6 }

  condition:
    any of them
}