rule TTP_XOR_WriteProcessMemory_ee03 {
  strings:
    $key_ee03 = { b9 71 [2] 8b 53 [2] 8d 66 [2] a3 66 [2] 9c 7a }

  condition:
    any of them
}