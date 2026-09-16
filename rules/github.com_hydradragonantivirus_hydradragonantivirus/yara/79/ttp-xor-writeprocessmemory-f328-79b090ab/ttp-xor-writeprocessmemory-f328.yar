rule TTP_XOR_WriteProcessMemory_f328 {
  strings:
    $key_f328 = { a4 5a [2] 96 78 [2] 90 4d [2] be 4d [2] 81 51 }

  condition:
    any of them
}