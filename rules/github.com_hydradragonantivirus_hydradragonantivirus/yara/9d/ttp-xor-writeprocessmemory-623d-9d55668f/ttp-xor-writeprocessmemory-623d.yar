rule TTP_XOR_WriteProcessMemory_623d {
  strings:
    $key_623d = { 35 4f [2] 07 6d [2] 01 58 [2] 2f 58 [2] 10 44 }

  condition:
    any of them
}