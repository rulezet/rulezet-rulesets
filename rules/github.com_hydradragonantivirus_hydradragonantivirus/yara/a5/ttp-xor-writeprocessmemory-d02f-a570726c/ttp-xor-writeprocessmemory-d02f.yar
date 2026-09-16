rule TTP_XOR_WriteProcessMemory_d02f {
  strings:
    $key_d02f = { 87 5d [2] b5 7f [2] b3 4a [2] 9d 4a [2] a2 56 }

  condition:
    any of them
}