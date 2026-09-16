rule TTP_XOR_WriteProcessMemory_0ce4 {
  strings:
    $key_0ce4 = { 5b 96 [2] 69 b4 [2] 6f 81 [2] 41 81 [2] 7e 9d }

  condition:
    any of them
}