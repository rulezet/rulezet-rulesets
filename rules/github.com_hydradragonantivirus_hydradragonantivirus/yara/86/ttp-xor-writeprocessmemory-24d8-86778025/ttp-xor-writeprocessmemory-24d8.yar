rule TTP_XOR_WriteProcessMemory_24d8 {
  strings:
    $key_24d8 = { 73 aa [2] 41 88 [2] 47 bd [2] 69 bd [2] 56 a1 }

  condition:
    any of them
}