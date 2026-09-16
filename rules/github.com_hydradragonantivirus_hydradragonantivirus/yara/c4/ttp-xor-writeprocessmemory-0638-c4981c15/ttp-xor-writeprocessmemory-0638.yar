rule TTP_XOR_WriteProcessMemory_0638 {
  strings:
    $key_0638 = { 51 4a [2] 63 68 [2] 65 5d [2] 4b 5d [2] 74 41 }

  condition:
    any of them
}