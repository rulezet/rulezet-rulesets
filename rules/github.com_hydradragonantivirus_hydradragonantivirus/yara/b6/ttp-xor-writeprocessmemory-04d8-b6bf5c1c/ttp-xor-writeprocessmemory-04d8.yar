rule TTP_XOR_WriteProcessMemory_04d8 {
  strings:
    $key_04d8 = { 53 aa [2] 61 88 [2] 67 bd [2] 49 bd [2] 76 a1 }

  condition:
    any of them
}