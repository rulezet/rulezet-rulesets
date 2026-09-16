rule TTP_XOR_WriteProcessMemory_679d {
  strings:
    $key_679d = { 30 ef [2] 02 cd [2] 04 f8 [2] 2a f8 [2] 15 e4 }

  condition:
    any of them
}