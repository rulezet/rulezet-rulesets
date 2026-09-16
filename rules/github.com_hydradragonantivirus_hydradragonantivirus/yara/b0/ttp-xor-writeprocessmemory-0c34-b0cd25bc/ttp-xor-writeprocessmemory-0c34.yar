rule TTP_XOR_WriteProcessMemory_0c34 {
  strings:
    $key_0c34 = { 5b 46 [2] 69 64 [2] 6f 51 [2] 41 51 [2] 7e 4d }

  condition:
    any of them
}