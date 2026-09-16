rule TTP_XOR_WriteProcessMemory_5237 {
  strings:
    $key_5237 = { 05 45 [2] 37 67 [2] 31 52 [2] 1f 52 [2] 20 4e }

  condition:
    any of them
}