rule TTP_XOR_WriteProcessMemory_629b {
  strings:
    $key_629b = { 35 e9 [2] 07 cb [2] 01 fe [2] 2f fe [2] 10 e2 }

  condition:
    any of them
}