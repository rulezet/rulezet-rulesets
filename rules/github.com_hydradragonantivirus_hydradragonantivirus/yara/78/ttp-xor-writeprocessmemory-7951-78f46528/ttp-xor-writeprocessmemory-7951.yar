rule TTP_XOR_WriteProcessMemory_7951 {
  strings:
    $key_7951 = { 2e 23 [2] 1c 01 [2] 1a 34 [2] 34 34 [2] 0b 28 }

  condition:
    any of them
}