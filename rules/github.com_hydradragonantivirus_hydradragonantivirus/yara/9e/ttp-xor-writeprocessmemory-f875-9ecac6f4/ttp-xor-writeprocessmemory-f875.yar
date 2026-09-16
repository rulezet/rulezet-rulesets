rule TTP_XOR_WriteProcessMemory_f875 {
  strings:
    $key_f875 = { af 07 [2] 9d 25 [2] 9b 10 [2] b5 10 [2] 8a 0c }

  condition:
    any of them
}