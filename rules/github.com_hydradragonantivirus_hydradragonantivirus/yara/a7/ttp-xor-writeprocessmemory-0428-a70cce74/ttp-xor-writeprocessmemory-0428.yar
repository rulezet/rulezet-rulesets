rule TTP_XOR_WriteProcessMemory_0428 {
  strings:
    $key_0428 = { 53 5a [2] 61 78 [2] 67 4d [2] 49 4d [2] 76 51 }

  condition:
    any of them
}