rule TTP_XOR_WriteProcessMemory_0693 {
  strings:
    $key_0693 = { 51 e1 [2] 63 c3 [2] 65 f6 [2] 4b f6 [2] 74 ea }

  condition:
    any of them
}