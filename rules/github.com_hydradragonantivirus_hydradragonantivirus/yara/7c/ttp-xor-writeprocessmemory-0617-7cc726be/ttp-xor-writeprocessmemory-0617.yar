rule TTP_XOR_WriteProcessMemory_0617 {
  strings:
    $key_0617 = { 51 65 [2] 63 47 [2] 65 72 [2] 4b 72 [2] 74 6e }

  condition:
    any of them
}