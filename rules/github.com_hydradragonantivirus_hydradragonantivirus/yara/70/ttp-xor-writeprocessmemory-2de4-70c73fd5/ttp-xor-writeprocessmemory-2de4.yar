rule TTP_XOR_WriteProcessMemory_2de4 {
  strings:
    $key_2de4 = { 7a 96 [2] 48 b4 [2] 4e 81 [2] 60 81 [2] 5f 9d }

  condition:
    any of them
}