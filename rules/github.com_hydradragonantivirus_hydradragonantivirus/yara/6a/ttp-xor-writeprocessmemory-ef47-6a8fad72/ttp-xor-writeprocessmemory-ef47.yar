rule TTP_XOR_WriteProcessMemory_ef47 {
  strings:
    $key_ef47 = { b8 35 [2] 8a 17 [2] 8c 22 [2] a2 22 [2] 9d 3e }

  condition:
    any of them
}