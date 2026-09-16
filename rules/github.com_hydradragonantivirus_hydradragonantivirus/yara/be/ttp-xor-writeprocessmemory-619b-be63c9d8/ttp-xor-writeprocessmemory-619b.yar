rule TTP_XOR_WriteProcessMemory_619b {
  strings:
    $key_619b = { 36 e9 [2] 04 cb [2] 02 fe [2] 2c fe [2] 13 e2 }

  condition:
    any of them
}