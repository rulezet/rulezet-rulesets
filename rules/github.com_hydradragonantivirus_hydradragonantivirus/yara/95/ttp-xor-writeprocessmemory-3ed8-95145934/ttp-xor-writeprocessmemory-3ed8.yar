rule TTP_XOR_WriteProcessMemory_3ed8 {
  strings:
    $key_3ed8 = { 69 aa [2] 5b 88 [2] 5d bd [2] 73 bd [2] 4c a1 }

  condition:
    any of them
}