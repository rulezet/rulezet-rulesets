rule TTP_XOR_WriteProcessMemory_bce4 {
  strings:
    $key_bce4 = { eb 96 [2] d9 b4 [2] df 81 [2] f1 81 [2] ce 9d }

  condition:
    any of them
}