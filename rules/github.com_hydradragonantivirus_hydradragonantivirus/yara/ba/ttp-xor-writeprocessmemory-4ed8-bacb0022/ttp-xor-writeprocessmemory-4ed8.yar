rule TTP_XOR_WriteProcessMemory_4ed8 {
  strings:
    $key_4ed8 = { 19 aa [2] 2b 88 [2] 2d bd [2] 03 bd [2] 3c a1 }

  condition:
    any of them
}