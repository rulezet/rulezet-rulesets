rule TTP_XOR_WriteProcessMemory_3e01 {
  strings:
    $key_3e01 = { 69 73 [2] 5b 51 [2] 5d 64 [2] 73 64 [2] 4c 78 }

  condition:
    any of them
}