rule TTP_XOR_WriteProcessMemory_4b53 {
  strings:
    $key_4b53 = { 1c 21 [2] 2e 03 [2] 28 36 [2] 06 36 [2] 39 2a }

  condition:
    any of them
}