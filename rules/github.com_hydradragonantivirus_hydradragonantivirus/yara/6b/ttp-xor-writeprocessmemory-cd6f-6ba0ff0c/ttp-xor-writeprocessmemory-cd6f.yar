rule TTP_XOR_WriteProcessMemory_cd6f {
  strings:
    $key_cd6f = { 9a 1d [2] a8 3f [2] ae 0a [2] 80 0a [2] bf 16 }

  condition:
    any of them
}