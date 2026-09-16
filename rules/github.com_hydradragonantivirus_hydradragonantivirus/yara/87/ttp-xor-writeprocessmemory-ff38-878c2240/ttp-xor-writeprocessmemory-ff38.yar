rule TTP_XOR_WriteProcessMemory_ff38 {
  strings:
    $key_ff38 = { a8 4a [2] 9a 68 [2] 9c 5d [2] b2 5d [2] 8d 41 }

  condition:
    any of them
}