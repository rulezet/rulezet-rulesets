rule TTP_XOR_WriteProcessMemory_3964 {
  strings:
    $key_3964 = { 6e 16 [2] 5c 34 [2] 5a 01 [2] 74 01 [2] 4b 1d }

  condition:
    any of them
}