rule TTP_XOR_WriteProcessMemory_3692 {
  strings:
    $key_3692 = { 61 e0 [2] 53 c2 [2] 55 f7 [2] 7b f7 [2] 44 eb }

  condition:
    any of them
}