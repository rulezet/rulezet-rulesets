rule TTP_XOR_WriteProcessMemory_2ed8 {
  strings:
    $key_2ed8 = { 79 aa [2] 4b 88 [2] 4d bd [2] 63 bd [2] 5c a1 }

  condition:
    any of them
}