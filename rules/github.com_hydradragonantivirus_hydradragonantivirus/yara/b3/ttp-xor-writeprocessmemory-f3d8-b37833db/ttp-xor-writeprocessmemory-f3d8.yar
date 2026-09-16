rule TTP_XOR_WriteProcessMemory_f3d8 {
  strings:
    $key_f3d8 = { a4 aa [2] 96 88 [2] 90 bd [2] be bd [2] 81 a1 }

  condition:
    any of them
}