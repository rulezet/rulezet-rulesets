rule TTP_XOR_WriteProcessMemory_fe37 {
  strings:
    $key_fe37 = { a9 45 [2] 9b 67 [2] 9d 52 [2] b3 52 [2] 8c 4e }

  condition:
    any of them
}