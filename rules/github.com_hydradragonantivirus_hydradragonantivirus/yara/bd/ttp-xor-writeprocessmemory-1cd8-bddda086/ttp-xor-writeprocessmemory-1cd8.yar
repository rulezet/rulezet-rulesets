rule TTP_XOR_WriteProcessMemory_1cd8 {
  strings:
    $key_1cd8 = { 4b aa [2] 79 88 [2] 7f bd [2] 51 bd [2] 6e a1 }

  condition:
    any of them
}