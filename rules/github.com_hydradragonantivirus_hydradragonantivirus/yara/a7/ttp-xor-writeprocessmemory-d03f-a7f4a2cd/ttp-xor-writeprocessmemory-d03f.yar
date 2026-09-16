rule TTP_XOR_WriteProcessMemory_d03f {
  strings:
    $key_d03f = { 87 4d [2] b5 6f [2] b3 5a [2] 9d 5a [2] a2 46 }

  condition:
    any of them
}