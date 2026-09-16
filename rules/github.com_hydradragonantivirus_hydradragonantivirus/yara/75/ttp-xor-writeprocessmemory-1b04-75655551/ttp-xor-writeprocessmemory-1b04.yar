rule TTP_XOR_WriteProcessMemory_1b04 {
  strings:
    $key_1b04 = { 4c 76 [2] 7e 54 [2] 78 61 [2] 56 61 [2] 69 7d }

  condition:
    any of them
}