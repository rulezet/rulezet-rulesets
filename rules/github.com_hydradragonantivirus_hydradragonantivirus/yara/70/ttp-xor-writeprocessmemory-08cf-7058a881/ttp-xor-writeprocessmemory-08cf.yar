rule TTP_XOR_WriteProcessMemory_08cf {
  strings:
    $key_08cf = { 5f bd [2] 6d 9f [2] 6b aa [2] 45 aa [2] 7a b6 }

  condition:
    any of them
}