rule TTP_XOR_WriteProcessMemory_0613 {
  strings:
    $key_0613 = { 51 61 [2] 63 43 [2] 65 76 [2] 4b 76 [2] 74 6a }

  condition:
    any of them
}