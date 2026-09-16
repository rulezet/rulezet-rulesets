rule TTP_XOR_WriteProcessMemory_0203 {
  strings:
    $key_0203 = { 55 71 [2] 67 53 [2] 61 66 [2] 4f 66 [2] 70 7a }

  condition:
    any of them
}