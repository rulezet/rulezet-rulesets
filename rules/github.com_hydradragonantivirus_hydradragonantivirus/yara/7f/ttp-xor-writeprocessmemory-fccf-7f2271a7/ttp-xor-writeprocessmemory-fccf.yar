rule TTP_XOR_WriteProcessMemory_fccf {
  strings:
    $key_fccf = { ab bd [2] 99 9f [2] 9f aa [2] b1 aa [2] 8e b6 }

  condition:
    any of them
}