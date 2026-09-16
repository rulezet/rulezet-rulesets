rule TTP_XOR_WriteProcessMemory_fb04 {
  strings:
    $key_fb04 = { ac 76 [2] 9e 54 [2] 98 61 [2] b6 61 [2] 89 7d }

  condition:
    any of them
}