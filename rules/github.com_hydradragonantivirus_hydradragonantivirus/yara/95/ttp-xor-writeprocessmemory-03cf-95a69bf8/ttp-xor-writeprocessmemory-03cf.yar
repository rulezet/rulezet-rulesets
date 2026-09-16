rule TTP_XOR_WriteProcessMemory_03cf {
  strings:
    $key_03cf = { 54 bd [2] 66 9f [2] 60 aa [2] 4e aa [2] 71 b6 }

  condition:
    any of them
}