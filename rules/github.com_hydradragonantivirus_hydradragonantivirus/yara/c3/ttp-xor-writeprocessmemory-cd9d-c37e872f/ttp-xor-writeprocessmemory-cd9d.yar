rule TTP_XOR_WriteProcessMemory_cd9d {
  strings:
    $key_cd9d = { 9a ef [2] a8 cd [2] ae f8 [2] 80 f8 [2] bf e4 }

  condition:
    any of them
}