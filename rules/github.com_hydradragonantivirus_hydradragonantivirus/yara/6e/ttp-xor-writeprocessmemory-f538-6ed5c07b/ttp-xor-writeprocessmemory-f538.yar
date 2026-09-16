rule TTP_XOR_WriteProcessMemory_f538 {
  strings:
    $key_f538 = { a2 4a [2] 90 68 [2] 96 5d [2] b8 5d [2] 87 41 }

  condition:
    any of them
}