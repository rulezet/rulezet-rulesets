rule TTP_XOR_WriteProcessMemory_0c24 {
  strings:
    $key_0c24 = { 5b 56 [2] 69 74 [2] 6f 41 [2] 41 41 [2] 7e 5d }

  condition:
    any of them
}