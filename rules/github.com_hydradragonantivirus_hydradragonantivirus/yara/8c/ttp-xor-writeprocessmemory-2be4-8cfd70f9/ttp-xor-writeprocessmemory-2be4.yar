rule TTP_XOR_WriteProcessMemory_2be4 {
  strings:
    $key_2be4 = { 7c 96 [2] 4e b4 [2] 48 81 [2] 66 81 [2] 59 9d }

  condition:
    any of them
}