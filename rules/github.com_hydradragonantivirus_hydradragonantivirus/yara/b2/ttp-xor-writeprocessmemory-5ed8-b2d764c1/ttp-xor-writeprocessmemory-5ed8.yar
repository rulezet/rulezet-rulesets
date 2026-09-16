rule TTP_XOR_WriteProcessMemory_5ed8 {
  strings:
    $key_5ed8 = { 09 aa [2] 3b 88 [2] 3d bd [2] 13 bd [2] 2c a1 }

  condition:
    any of them
}