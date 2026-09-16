rule TTP_XOR_WriteProcessMemory_cd4a {
  strings:
    $key_cd4a = { 9a 38 [2] a8 1a [2] ae 2f [2] 80 2f [2] bf 33 }

  condition:
    any of them
}