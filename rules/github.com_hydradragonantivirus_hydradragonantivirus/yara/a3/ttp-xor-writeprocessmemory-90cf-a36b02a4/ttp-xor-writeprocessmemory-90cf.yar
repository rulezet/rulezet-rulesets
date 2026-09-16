rule TTP_XOR_WriteProcessMemory_90cf {
  strings:
    $key_90cf = { c7 bd [2] f5 9f [2] f3 aa [2] dd aa [2] e2 b6 }

  condition:
    any of them
}