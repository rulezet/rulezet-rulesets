rule TTP_XOR_WriteProcessMemory_2411 {
  strings:
    $key_2411 = { 73 63 [2] 41 41 [2] 47 74 [2] 69 74 [2] 56 68 }

  condition:
    any of them
}