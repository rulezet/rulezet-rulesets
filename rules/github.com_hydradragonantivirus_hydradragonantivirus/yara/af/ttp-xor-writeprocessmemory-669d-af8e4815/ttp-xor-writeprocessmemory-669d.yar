rule TTP_XOR_WriteProcessMemory_669d {
  strings:
    $key_669d = { 31 ef [2] 03 cd [2] 05 f8 [2] 2b f8 [2] 14 e4 }

  condition:
    any of them
}