rule TTP_XOR_WriteProcessMemory_2bf4 {
  strings:
    $key_2bf4 = { 7c 86 [2] 4e a4 [2] 48 91 [2] 66 91 [2] 59 8d }

  condition:
    any of them
}