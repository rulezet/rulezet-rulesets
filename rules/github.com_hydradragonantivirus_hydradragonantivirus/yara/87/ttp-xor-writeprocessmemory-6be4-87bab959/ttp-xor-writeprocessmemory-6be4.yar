rule TTP_XOR_WriteProcessMemory_6be4 {
  strings:
    $key_6be4 = { 3c 96 [2] 0e b4 [2] 08 81 [2] 26 81 [2] 19 9d }

  condition:
    any of them
}