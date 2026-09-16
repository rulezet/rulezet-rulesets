rule TTP_XOR_WriteProcessMemory_0234 {
  strings:
    $key_0234 = { 55 46 [2] 67 64 [2] 61 51 [2] 4f 51 [2] 70 4d }

  condition:
    any of them
}