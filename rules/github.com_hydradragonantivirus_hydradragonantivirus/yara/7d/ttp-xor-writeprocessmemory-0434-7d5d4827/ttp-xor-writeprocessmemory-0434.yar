rule TTP_XOR_WriteProcessMemory_0434 {
  strings:
    $key_0434 = { 53 46 [2] 61 64 [2] 67 51 [2] 49 51 [2] 76 4d }

  condition:
    any of them
}