rule TTP_XOR_WriteProcessMemory_1ad8 {
  strings:
    $key_1ad8 = { 4d aa [2] 7f 88 [2] 79 bd [2] 57 bd [2] 68 a1 }

  condition:
    any of them
}