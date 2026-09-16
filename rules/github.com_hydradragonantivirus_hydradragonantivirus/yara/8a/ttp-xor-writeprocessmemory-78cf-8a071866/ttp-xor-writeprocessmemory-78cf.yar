rule TTP_XOR_WriteProcessMemory_78cf {
  strings:
    $key_78cf = { 2f bd [2] 1d 9f [2] 1b aa [2] 35 aa [2] 0a b6 }

  condition:
    any of them
}