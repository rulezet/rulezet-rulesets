rule TTP_XOR_WriteProcessMemory_4cd8 {
  strings:
    $key_4cd8 = { 1b aa [2] 29 88 [2] 2f bd [2] 01 bd [2] 3e a1 }

  condition:
    any of them
}