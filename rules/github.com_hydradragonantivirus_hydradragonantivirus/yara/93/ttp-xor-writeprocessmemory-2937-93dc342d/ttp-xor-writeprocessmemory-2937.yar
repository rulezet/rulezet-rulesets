rule TTP_XOR_WriteProcessMemory_2937 {
  strings:
    $key_2937 = { 7e 45 [2] 4c 67 [2] 4a 52 [2] 64 52 [2] 5b 4e }

  condition:
    any of them
}