rule TTP_XOR_WriteProcessMemory_7423 {
  strings:
    $key_7423 = { 23 51 [2] 11 73 [2] 17 46 [2] 39 46 [2] 06 5a }

  condition:
    any of them
}