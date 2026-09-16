rule TTP_XOR_WriteProcessMemory_e39d {
  strings:
    $key_e39d = { b4 ef [2] 86 cd [2] 80 f8 [2] ae f8 [2] 91 e4 }

  condition:
    any of them
}