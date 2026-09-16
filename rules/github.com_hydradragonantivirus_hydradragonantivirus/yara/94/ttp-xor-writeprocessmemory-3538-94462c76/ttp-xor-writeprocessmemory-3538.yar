rule TTP_XOR_WriteProcessMemory_3538 {
  strings:
    $key_3538 = { 62 4a [2] 50 68 [2] 56 5d [2] 78 5d [2] 47 41 }

  condition:
    any of them
}