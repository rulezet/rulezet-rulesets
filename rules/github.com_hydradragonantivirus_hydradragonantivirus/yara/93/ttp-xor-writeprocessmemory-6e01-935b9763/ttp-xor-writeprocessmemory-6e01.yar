rule TTP_XOR_WriteProcessMemory_6e01 {
  strings:
    $key_6e01 = { 39 73 [2] 0b 51 [2] 0d 64 [2] 23 64 [2] 1c 78 }

  condition:
    any of them
}