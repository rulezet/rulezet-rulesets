rule TTP_XOR_WriteProcessMemory_d018 {
  strings:
    $key_d018 = { 87 6a [2] b5 48 [2] b3 7d [2] 9d 7d [2] a2 61 }

  condition:
    any of them
}