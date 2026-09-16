rule TTP_XOR_WriteProcessMemory_cd3f {
  strings:
    $key_cd3f = { 9a 4d [2] a8 6f [2] ae 5a [2] 80 5a [2] bf 46 }

  condition:
    any of them
}