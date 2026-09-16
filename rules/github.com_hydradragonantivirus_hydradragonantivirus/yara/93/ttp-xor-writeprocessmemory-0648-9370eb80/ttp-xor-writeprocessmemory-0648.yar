rule TTP_XOR_WriteProcessMemory_0648 {
  strings:
    $key_0648 = { 51 3a [2] 63 18 [2] 65 2d [2] 4b 2d [2] 74 31 }

  condition:
    any of them
}