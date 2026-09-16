rule TTP_XOR_WriteProcessMemory_0667 {
  strings:
    $key_0667 = { 51 15 [2] 63 37 [2] 65 02 [2] 4b 02 [2] 74 1e }

  condition:
    any of them
}