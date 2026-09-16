rule TTP_XOR_WriteProcessMemory_fba6 {
  strings:
    $key_fba6 = { ac d4 [2] 9e f6 [2] 98 c3 [2] b6 c3 [2] 89 df }

  condition:
    any of them
}