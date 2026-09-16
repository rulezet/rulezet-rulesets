rule TTP_XOR_WriteProcessMemory_fa37 {
  strings:
    $key_fa37 = { ad 45 [2] 9f 67 [2] 99 52 [2] b7 52 [2] 88 4e }

  condition:
    any of them
}