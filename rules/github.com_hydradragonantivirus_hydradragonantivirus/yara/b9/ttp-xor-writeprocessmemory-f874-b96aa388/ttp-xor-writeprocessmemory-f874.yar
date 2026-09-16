rule TTP_XOR_WriteProcessMemory_f874 {
  strings:
    $key_f874 = { af 06 [2] 9d 24 [2] 9b 11 [2] b5 11 [2] 8a 0d }

  condition:
    any of them
}