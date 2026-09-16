rule TTP_XOR_WriteProcessMemory_da38 {
  strings:
    $key_da38 = { 8d 4a [2] bf 68 [2] b9 5d [2] 97 5d [2] a8 41 }

  condition:
    any of them
}