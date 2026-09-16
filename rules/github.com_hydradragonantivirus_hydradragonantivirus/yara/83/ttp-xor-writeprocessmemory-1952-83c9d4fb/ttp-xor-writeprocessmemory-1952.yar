rule TTP_XOR_WriteProcessMemory_1952 {
  strings:
    $key_1952 = { 4e 20 [2] 7c 02 [2] 7a 37 [2] 54 37 [2] 6b 2b }

  condition:
    any of them
}