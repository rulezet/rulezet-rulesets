rule TTP_XOR_WriteProcessMemory_1de8 {
  strings:
    $key_1de8 = { 4a 9a [2] 78 b8 [2] 7e 8d [2] 50 8d [2] 6f 91 }

  condition:
    any of them
}