rule TTP_XOR_WriteProcessMemory_ec93 {
  strings:
    $key_ec93 = { bb e1 [2] 89 c3 [2] 8f f6 [2] a1 f6 [2] 9e ea }

  condition:
    any of them
}