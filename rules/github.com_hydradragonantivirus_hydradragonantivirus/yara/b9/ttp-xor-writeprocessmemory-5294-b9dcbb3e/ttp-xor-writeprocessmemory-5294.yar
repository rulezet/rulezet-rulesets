rule TTP_XOR_WriteProcessMemory_5294 {
  strings:
    $key_5294 = { 05 e6 [2] 37 c4 [2] 31 f1 [2] 1f f1 [2] 20 ed }

  condition:
    any of them
}