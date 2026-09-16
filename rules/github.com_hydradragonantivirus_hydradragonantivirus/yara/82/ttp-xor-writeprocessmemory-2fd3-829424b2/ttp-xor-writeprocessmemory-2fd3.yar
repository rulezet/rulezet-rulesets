rule TTP_XOR_WriteProcessMemory_2fd3 {
  strings:
    $key_2fd3 = { 78 a1 [2] 4a 83 [2] 4c b6 [2] 62 b6 [2] 5d aa }

  condition:
    any of them
}