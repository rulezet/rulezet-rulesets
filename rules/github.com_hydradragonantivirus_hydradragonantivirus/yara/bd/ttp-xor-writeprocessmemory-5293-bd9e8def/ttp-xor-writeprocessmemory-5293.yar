rule TTP_XOR_WriteProcessMemory_5293 {
  strings:
    $key_5293 = { 05 e1 [2] 37 c3 [2] 31 f6 [2] 1f f6 [2] 20 ea }

  condition:
    any of them
}