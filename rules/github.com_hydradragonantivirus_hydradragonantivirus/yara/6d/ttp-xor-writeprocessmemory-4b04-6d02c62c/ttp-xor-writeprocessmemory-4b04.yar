rule TTP_XOR_WriteProcessMemory_4b04 {
  strings:
    $key_4b04 = { 1c 76 [2] 2e 54 [2] 28 61 [2] 06 61 [2] 39 7d }

  condition:
    any of them
}