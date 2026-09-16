rule TTP_XOR_WriteProcessMemory_cd0a {
  strings:
    $key_cd0a = { 9a 78 [2] a8 5a [2] ae 6f [2] 80 6f [2] bf 73 }

  condition:
    any of them
}