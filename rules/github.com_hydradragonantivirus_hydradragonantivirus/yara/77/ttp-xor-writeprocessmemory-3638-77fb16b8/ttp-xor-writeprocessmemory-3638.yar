rule TTP_XOR_WriteProcessMemory_3638 {
  strings:
    $key_3638 = { 61 4a [2] 53 68 [2] 55 5d [2] 7b 5d [2] 44 41 }

  condition:
    any of them
}