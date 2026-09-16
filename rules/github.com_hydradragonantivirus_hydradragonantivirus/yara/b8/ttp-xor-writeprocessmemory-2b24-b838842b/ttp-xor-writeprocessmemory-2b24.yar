rule TTP_XOR_WriteProcessMemory_2b24 {
  strings:
    $key_2b24 = { 7c 56 [2] 4e 74 [2] 48 41 [2] 66 41 [2] 59 5d }

  condition:
    any of them
}