rule TTP_XOR_WriteProcessMemory_5b24 {
  strings:
    $key_5b24 = { 0c 56 [2] 3e 74 [2] 38 41 [2] 16 41 [2] 29 5d }

  condition:
    any of them
}