rule TTP_XOR_WriteProcessMemory_0ed8 {
  strings:
    $key_0ed8 = { 59 aa [2] 6b 88 [2] 6d bd [2] 43 bd [2] 7c a1 }

  condition:
    any of them
}