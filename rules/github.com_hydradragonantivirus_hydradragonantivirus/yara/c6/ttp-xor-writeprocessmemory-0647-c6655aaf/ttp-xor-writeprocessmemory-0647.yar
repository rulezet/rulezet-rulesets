rule TTP_XOR_WriteProcessMemory_0647 {
  strings:
    $key_0647 = { 51 35 [2] 63 17 [2] 65 22 [2] 4b 22 [2] 74 3e }

  condition:
    any of them
}