rule TTP_XOR_WriteProcessMemory_fce4 {
  strings:
    $key_fce4 = { ab 96 [2] 99 b4 [2] 9f 81 [2] b1 81 [2] 8e 9d }

  condition:
    any of them
}