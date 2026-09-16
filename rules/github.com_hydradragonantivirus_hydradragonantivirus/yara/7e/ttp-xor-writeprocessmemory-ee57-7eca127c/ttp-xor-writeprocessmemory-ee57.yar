rule TTP_XOR_WriteProcessMemory_ee57 {
  strings:
    $key_ee57 = { b9 25 [2] 8b 07 [2] 8d 32 [2] a3 32 [2] 9c 2e }

  condition:
    any of them
}