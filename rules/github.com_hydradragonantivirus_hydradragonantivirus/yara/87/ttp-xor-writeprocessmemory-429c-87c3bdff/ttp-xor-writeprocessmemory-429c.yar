rule TTP_XOR_WriteProcessMemory_429c {
  strings:
    $key_429c = { 15 ee [2] 27 cc [2] 21 f9 [2] 0f f9 [2] 30 e5 }

  condition:
    any of them
}