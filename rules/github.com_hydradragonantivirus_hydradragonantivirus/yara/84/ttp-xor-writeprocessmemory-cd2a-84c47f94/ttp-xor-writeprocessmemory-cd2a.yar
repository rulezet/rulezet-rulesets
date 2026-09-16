rule TTP_XOR_WriteProcessMemory_cd2a {
  strings:
    $key_cd2a = { 9a 58 [2] a8 7a [2] ae 4f [2] 80 4f [2] bf 53 }

  condition:
    any of them
}