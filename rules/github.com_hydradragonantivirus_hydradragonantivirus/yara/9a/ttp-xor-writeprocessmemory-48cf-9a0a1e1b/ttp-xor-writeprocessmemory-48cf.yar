rule TTP_XOR_WriteProcessMemory_48cf {
  strings:
    $key_48cf = { 1f bd [2] 2d 9f [2] 2b aa [2] 05 aa [2] 3a b6 }

  condition:
    any of them
}