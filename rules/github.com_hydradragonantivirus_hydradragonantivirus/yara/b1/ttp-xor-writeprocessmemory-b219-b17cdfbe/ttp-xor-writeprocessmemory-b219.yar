rule TTP_XOR_WriteProcessMemory_b219 {
  strings:
    $key_b219 = { e5 6b [2] d7 49 [2] d1 7c [2] ff 7c [2] c0 60 }

  condition:
    any of them
}