rule TTP_XOR_WriteProcessMemory_ee39 {
  strings:
    $key_ee39 = { b9 4b [2] 8b 69 [2] 8d 5c [2] a3 5c [2] 9c 40 }

  condition:
    any of them
}