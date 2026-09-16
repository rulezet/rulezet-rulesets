rule TTP_XOR_WriteProcessMemory_cd3a {
  strings:
    $key_cd3a = { 9a 48 [2] a8 6a [2] ae 5f [2] 80 5f [2] bf 43 }

  condition:
    any of them
}