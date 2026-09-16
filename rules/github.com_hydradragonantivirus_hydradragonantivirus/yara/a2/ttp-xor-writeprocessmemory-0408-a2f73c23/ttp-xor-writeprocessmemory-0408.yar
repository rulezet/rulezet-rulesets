rule TTP_XOR_WriteProcessMemory_0408 {
  strings:
    $key_0408 = { 53 7a [2] 61 58 [2] 67 6d [2] 49 6d [2] 76 71 }

  condition:
    any of them
}