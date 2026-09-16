rule TTP_XOR_WriteProcessMemory_529c {
  strings:
    $key_529c = { 05 ee [2] 37 cc [2] 31 f9 [2] 1f f9 [2] 20 e5 }

  condition:
    any of them
}