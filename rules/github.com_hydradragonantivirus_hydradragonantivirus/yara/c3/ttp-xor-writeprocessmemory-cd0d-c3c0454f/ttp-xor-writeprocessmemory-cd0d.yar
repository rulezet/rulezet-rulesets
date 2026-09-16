rule TTP_XOR_WriteProcessMemory_cd0d {
  strings:
    $key_cd0d = { 9a 7f [2] a8 5d [2] ae 68 [2] 80 68 [2] bf 74 }

  condition:
    any of them
}