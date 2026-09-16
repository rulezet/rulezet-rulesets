rule TTP_XOR_WriteProcessMemory_db8c {
  strings:
    $key_db8c = { 8c fe [2] be dc [2] b8 e9 [2] 96 e9 [2] a9 f5 }

  condition:
    any of them
}