rule TTP_XOR_WriteProcessMemory_ca8c {
  strings:
    $key_ca8c = { 9d fe [2] af dc [2] a9 e9 [2] 87 e9 [2] b8 f5 }

  condition:
    any of them
}