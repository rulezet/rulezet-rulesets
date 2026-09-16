rule TTP_XOR_WriteProcessMemory_edd2 {
  strings:
    $key_edd2 = { ba a0 [2] 88 82 [2] 8e b7 [2] a0 b7 [2] 9f ab }

  condition:
    any of them
}