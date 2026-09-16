rule TTP_XOR_WriteProcessMemory_2b38 {
  strings:
    $key_2b38 = { 7c 4a [2] 4e 68 [2] 48 5d [2] 66 5d [2] 59 41 }

  condition:
    any of them
}