rule TTP_XOR_WriteProcessMemory_0c52 {
  strings:
    $key_0c52 = { 5b 20 [2] 69 02 [2] 6f 37 [2] 41 37 [2] 7e 2b }

  condition:
    any of them
}