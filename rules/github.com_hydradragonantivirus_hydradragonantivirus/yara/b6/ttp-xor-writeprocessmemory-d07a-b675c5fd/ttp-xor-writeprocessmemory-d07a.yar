rule TTP_XOR_WriteProcessMemory_d07a {
  strings:
    $key_d07a = { 87 08 [2] b5 2a [2] b3 1f [2] 9d 1f [2] a2 03 }

  condition:
    any of them
}