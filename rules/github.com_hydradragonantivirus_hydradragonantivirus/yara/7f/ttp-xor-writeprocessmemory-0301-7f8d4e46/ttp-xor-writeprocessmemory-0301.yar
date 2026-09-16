rule TTP_XOR_WriteProcessMemory_0301 {
  strings:
    $key_0301 = { 54 73 [2] 66 51 [2] 60 64 [2] 4e 64 [2] 71 78 }

  condition:
    any of them
}