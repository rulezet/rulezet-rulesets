rule TTP_XOR_WriteProcessMemory_d09b {
  strings:
    $key_d09b = { 87 e9 [2] b5 cb [2] b3 fe [2] 9d fe [2] a2 e2 }

  condition:
    any of them
}