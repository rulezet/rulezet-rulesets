rule TTP_XOR_WriteProcessMemory_0c01 {
  strings:
    $key_0c01 = { 5b 73 [2] 69 51 [2] 6f 64 [2] 41 64 [2] 7e 78 }

  condition:
    any of them
}