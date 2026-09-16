rule TTP_XOR_WriteProcessMemory_d52f {
  strings:
    $key_d52f = { 82 5d [2] b0 7f [2] b6 4a [2] 98 4a [2] a7 56 }

  condition:
    any of them
}