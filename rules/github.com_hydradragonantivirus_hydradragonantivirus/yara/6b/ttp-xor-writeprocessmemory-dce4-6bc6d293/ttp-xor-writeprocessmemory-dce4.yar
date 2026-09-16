rule TTP_XOR_WriteProcessMemory_dce4 {
  strings:
    $key_dce4 = { 8b 96 [2] b9 b4 [2] bf 81 [2] 91 81 [2] ae 9d }

  condition:
    any of them
}