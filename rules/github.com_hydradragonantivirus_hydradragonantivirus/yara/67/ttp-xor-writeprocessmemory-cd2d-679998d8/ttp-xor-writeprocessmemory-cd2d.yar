rule TTP_XOR_WriteProcessMemory_cd2d {
  strings:
    $key_cd2d = { 9a 5f [2] a8 7d [2] ae 48 [2] 80 48 [2] bf 54 }

  condition:
    any of them
}