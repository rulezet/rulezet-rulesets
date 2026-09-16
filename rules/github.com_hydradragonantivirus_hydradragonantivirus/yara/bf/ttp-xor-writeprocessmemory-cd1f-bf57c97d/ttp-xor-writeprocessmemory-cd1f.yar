rule TTP_XOR_WriteProcessMemory_cd1f {
  strings:
    $key_cd1f = { 9a 6d [2] a8 4f [2] ae 7a [2] 80 7a [2] bf 66 }

  condition:
    any of them
}